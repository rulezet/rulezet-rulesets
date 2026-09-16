rule TTP_XOR_QUAD_CurrentVersionRun_2605 {
  strings:
    $key_2605 = { 75 6a [2] 51 64 [2] 7a 48 [2] 54 6a [2] 40 71 [2] 4f 6b [2] 51 76 [2] 53 77 [2] 48 71 [2] 54 76 [2] 48 59 }

  condition:
    any of them
}