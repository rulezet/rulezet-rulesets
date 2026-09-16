rule TTP_XOR_QUAD_CurrentVersionRun_143b {
  strings:
    $key_143b = { 47 54 [2] 63 5a [2] 48 76 [2] 66 54 [2] 72 4f [2] 7d 55 [2] 63 48 [2] 61 49 [2] 7a 4f [2] 66 48 [2] 7a 67 }

  condition:
    any of them
}