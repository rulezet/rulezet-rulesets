rule TTP_XOR_QUAD_CurrentVersionRun_313b {
  strings:
    $key_313b = { 62 54 [2] 46 5a [2] 6d 76 [2] 43 54 [2] 57 4f [2] 58 55 [2] 46 48 [2] 44 49 [2] 5f 4f [2] 43 48 [2] 5f 67 }

  condition:
    any of them
}