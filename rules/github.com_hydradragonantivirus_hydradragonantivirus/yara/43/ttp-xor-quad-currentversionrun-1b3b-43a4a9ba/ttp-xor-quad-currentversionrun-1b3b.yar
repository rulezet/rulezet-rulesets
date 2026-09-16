rule TTP_XOR_QUAD_CurrentVersionRun_1b3b {
  strings:
    $key_1b3b = { 48 54 [2] 6c 5a [2] 47 76 [2] 69 54 [2] 7d 4f [2] 72 55 [2] 6c 48 [2] 6e 49 [2] 75 4f [2] 69 48 [2] 75 67 }

  condition:
    any of them
}