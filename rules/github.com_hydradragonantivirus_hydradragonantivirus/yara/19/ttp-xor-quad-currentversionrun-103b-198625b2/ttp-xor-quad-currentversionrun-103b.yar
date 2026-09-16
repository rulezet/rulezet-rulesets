rule TTP_XOR_QUAD_CurrentVersionRun_103b {
  strings:
    $key_103b = { 43 54 [2] 67 5a [2] 4c 76 [2] 62 54 [2] 76 4f [2] 79 55 [2] 67 48 [2] 65 49 [2] 7e 4f [2] 62 48 [2] 7e 67 }

  condition:
    any of them
}