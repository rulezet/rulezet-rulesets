rule TTP_XOR_QUAD_CurrentVersionRun_de72 {
  strings:
    $key_de72 = { 8d 1d [2] a9 13 [2] 82 3f [2] ac 1d [2] b8 06 [2] b7 1c [2] a9 01 [2] ab 00 [2] b0 06 [2] ac 01 [2] b0 2e }

  condition:
    any of them
}