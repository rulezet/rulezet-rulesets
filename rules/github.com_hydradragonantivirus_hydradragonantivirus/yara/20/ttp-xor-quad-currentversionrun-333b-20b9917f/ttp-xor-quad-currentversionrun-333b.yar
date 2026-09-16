rule TTP_XOR_QUAD_CurrentVersionRun_333b {
  strings:
    $key_333b = { 60 54 [2] 44 5a [2] 6f 76 [2] 41 54 [2] 55 4f [2] 5a 55 [2] 44 48 [2] 46 49 [2] 5d 4f [2] 41 48 [2] 5d 67 }

  condition:
    any of them
}