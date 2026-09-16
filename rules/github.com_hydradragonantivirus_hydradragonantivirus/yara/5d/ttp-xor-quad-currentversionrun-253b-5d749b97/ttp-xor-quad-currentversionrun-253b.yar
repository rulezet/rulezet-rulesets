rule TTP_XOR_QUAD_CurrentVersionRun_253b {
  strings:
    $key_253b = { 76 54 [2] 52 5a [2] 79 76 [2] 57 54 [2] 43 4f [2] 4c 55 [2] 52 48 [2] 50 49 [2] 4b 4f [2] 57 48 [2] 4b 67 }

  condition:
    any of them
}