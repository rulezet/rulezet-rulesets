rule TTP_XOR_QUAD_CurrentVersionRun_3b47 {
  strings:
    $key_3b47 = { 68 28 [2] 4c 26 [2] 67 0a [2] 49 28 [2] 5d 33 [2] 52 29 [2] 4c 34 [2] 4e 35 [2] 55 33 [2] 49 34 [2] 55 1b }

  condition:
    any of them
}