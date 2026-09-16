rule TTP_XOR_QUAD_CurrentVersionRun_e469 {
  strings:
    $key_e469 = { b7 06 [2] 93 08 [2] b8 24 [2] 96 06 [2] 82 1d [2] 8d 07 [2] 93 1a [2] 91 1b [2] 8a 1d [2] 96 1a [2] 8a 35 }

  condition:
    any of them
}