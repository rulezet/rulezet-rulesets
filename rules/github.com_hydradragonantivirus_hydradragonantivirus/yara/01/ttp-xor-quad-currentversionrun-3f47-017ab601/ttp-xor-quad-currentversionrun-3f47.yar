rule TTP_XOR_QUAD_CurrentVersionRun_3f47 {
  strings:
    $key_3f47 = { 6c 28 [2] 48 26 [2] 63 0a [2] 4d 28 [2] 59 33 [2] 56 29 [2] 48 34 [2] 4a 35 [2] 51 33 [2] 4d 34 [2] 51 1b }

  condition:
    any of them
}