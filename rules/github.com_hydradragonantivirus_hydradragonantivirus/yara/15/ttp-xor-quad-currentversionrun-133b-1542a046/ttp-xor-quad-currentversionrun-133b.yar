rule TTP_XOR_QUAD_CurrentVersionRun_133b {
  strings:
    $key_133b = { 40 54 [2] 64 5a [2] 4f 76 [2] 61 54 [2] 75 4f [2] 7a 55 [2] 64 48 [2] 66 49 [2] 7d 4f [2] 61 48 [2] 7d 67 }

  condition:
    any of them
}