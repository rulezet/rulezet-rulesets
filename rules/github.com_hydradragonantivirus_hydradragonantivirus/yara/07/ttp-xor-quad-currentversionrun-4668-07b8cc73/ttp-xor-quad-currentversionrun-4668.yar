rule TTP_XOR_QUAD_CurrentVersionRun_4668 {
  strings:
    $key_4668 = { 15 07 [2] 31 09 [2] 1a 25 [2] 34 07 [2] 20 1c [2] 2f 06 [2] 31 1b [2] 33 1a [2] 28 1c [2] 34 1b [2] 28 34 }

  condition:
    any of them
}