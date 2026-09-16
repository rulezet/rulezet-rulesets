rule TTP_XOR_QUAD_CurrentVersionRun_de1e {
  strings:
    $key_de1e = { 8d 71 [2] a9 7f [2] 82 53 [2] ac 71 [2] b8 6a [2] b7 70 [2] a9 6d [2] ab 6c [2] b0 6a [2] ac 6d [2] b0 42 }

  condition:
    any of them
}