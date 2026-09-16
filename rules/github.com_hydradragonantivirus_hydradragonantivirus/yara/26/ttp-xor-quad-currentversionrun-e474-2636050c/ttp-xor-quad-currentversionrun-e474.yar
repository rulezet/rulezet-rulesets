rule TTP_XOR_QUAD_CurrentVersionRun_e474 {
  strings:
    $key_e474 = { b7 1b [2] 93 15 [2] b8 39 [2] 96 1b [2] 82 00 [2] 8d 1a [2] 93 07 [2] 91 06 [2] 8a 00 [2] 96 07 [2] 8a 28 }

  condition:
    any of them
}