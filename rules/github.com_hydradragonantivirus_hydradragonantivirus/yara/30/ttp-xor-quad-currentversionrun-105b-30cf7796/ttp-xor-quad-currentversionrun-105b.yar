rule TTP_XOR_QUAD_CurrentVersionRun_105b {
  strings:
    $key_105b = { 43 34 [2] 67 3a [2] 4c 16 [2] 62 34 [2] 76 2f [2] 79 35 [2] 67 28 [2] 65 29 [2] 7e 2f [2] 62 28 [2] 7e 07 }

  condition:
    any of them
}