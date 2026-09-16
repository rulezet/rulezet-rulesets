rule TTP_XOR_QUAD_CurrentVersionRun_e468 {
  strings:
    $key_e468 = { b7 07 [2] 93 09 [2] b8 25 [2] 96 07 [2] 82 1c [2] 8d 06 [2] 93 1b [2] 91 1a [2] 8a 1c [2] 96 1b [2] 8a 34 }

  condition:
    any of them
}