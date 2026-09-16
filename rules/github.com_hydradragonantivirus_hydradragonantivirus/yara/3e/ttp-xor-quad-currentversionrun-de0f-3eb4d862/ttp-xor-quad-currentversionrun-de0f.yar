rule TTP_XOR_QUAD_CurrentVersionRun_de0f {
  strings:
    $key_de0f = { 8d 60 [2] a9 6e [2] 82 42 [2] ac 60 [2] b8 7b [2] b7 61 [2] a9 7c [2] ab 7d [2] b0 7b [2] ac 7c [2] b0 53 }

  condition:
    any of them
}