rule TTP_XOR_QUAD_CurrentVersionRun_393b {
  strings:
    $key_393b = { 6a 54 [2] 4e 5a [2] 65 76 [2] 4b 54 [2] 5f 4f [2] 50 55 [2] 4e 48 [2] 4c 49 [2] 57 4f [2] 4b 48 [2] 57 67 }

  condition:
    any of them
}