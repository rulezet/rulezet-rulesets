rule TTP_XOR_QUAD_CurrentVersionRun_1f3b {
  strings:
    $key_1f3b = { 4c 54 [2] 68 5a [2] 43 76 [2] 6d 54 [2] 79 4f [2] 76 55 [2] 68 48 [2] 6a 49 [2] 71 4f [2] 6d 48 [2] 71 67 }

  condition:
    any of them
}