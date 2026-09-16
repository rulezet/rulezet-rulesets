rule TTP_XOR_QUAD_CurrentVersionRun_073b {
  strings:
    $key_073b = { 54 54 [2] 70 5a [2] 5b 76 [2] 75 54 [2] 61 4f [2] 6e 55 [2] 70 48 [2] 72 49 [2] 69 4f [2] 75 48 [2] 69 67 }

  condition:
    any of them
}