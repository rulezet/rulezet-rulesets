rule TTP_XOR_QUAD_CurrentVersionRun_6b3b {
  strings:
    $key_6b3b = { 38 54 [2] 1c 5a [2] 37 76 [2] 19 54 [2] 0d 4f [2] 02 55 [2] 1c 48 [2] 1e 49 [2] 05 4f [2] 19 48 [2] 05 67 }

  condition:
    any of them
}