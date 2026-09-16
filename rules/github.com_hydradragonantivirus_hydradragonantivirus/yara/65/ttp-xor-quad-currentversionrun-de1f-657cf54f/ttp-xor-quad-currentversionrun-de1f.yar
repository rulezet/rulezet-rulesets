rule TTP_XOR_QUAD_CurrentVersionRun_de1f {
  strings:
    $key_de1f = { 8d 70 [2] a9 7e [2] 82 52 [2] ac 70 [2] b8 6b [2] b7 71 [2] a9 6c [2] ab 6d [2] b0 6b [2] ac 6c [2] b0 43 }

  condition:
    any of them
}