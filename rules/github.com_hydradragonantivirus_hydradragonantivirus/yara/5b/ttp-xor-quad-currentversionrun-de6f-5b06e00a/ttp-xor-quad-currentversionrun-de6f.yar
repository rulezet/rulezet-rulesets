rule TTP_XOR_QUAD_CurrentVersionRun_de6f {
  strings:
    $key_de6f = { 8d 00 [2] a9 0e [2] 82 22 [2] ac 00 [2] b8 1b [2] b7 01 [2] a9 1c [2] ab 1d [2] b0 1b [2] ac 1c [2] b0 33 }

  condition:
    any of them
}