rule TTP_XOR_QUAD_CurrentVersionRun_6c3b {
  strings:
    $key_6c3b = { 3f 54 [2] 1b 5a [2] 30 76 [2] 1e 54 [2] 0a 4f [2] 05 55 [2] 1b 48 [2] 19 49 [2] 02 4f [2] 1e 48 [2] 02 67 }

  condition:
    any of them
}