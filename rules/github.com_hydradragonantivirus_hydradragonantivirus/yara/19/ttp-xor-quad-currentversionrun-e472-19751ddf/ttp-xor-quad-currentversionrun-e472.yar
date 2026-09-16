rule TTP_XOR_QUAD_CurrentVersionRun_e472 {
  strings:
    $key_e472 = { b7 1d [2] 93 13 [2] b8 3f [2] 96 1d [2] 82 06 [2] 8d 1c [2] 93 01 [2] 91 00 [2] 8a 06 [2] 96 01 [2] 8a 2e }

  condition:
    any of them
}