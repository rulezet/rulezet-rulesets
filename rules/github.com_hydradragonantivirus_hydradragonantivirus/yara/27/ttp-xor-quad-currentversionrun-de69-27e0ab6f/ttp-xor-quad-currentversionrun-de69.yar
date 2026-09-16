rule TTP_XOR_QUAD_CurrentVersionRun_de69 {
  strings:
    $key_de69 = { 8d 06 [2] a9 08 [2] 82 24 [2] ac 06 [2] b8 1d [2] b7 07 [2] a9 1a [2] ab 1b [2] b0 1d [2] ac 1a [2] b0 35 }

  condition:
    any of them
}