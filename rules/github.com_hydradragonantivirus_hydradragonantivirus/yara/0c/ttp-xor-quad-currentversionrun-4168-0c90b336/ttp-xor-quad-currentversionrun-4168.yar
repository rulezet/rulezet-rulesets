rule TTP_XOR_QUAD_CurrentVersionRun_4168 {
  strings:
    $key_4168 = { 12 07 [2] 36 09 [2] 1d 25 [2] 33 07 [2] 27 1c [2] 28 06 [2] 36 1b [2] 34 1a [2] 2f 1c [2] 33 1b [2] 2f 34 }

  condition:
    any of them
}