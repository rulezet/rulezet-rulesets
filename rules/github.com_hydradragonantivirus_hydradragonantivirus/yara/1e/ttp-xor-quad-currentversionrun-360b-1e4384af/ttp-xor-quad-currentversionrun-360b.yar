rule TTP_XOR_QUAD_CurrentVersionRun_360b {
  strings:
    $key_360b = { 65 64 [2] 41 6a [2] 6a 46 [2] 44 64 [2] 50 7f [2] 5f 65 [2] 41 78 [2] 43 79 [2] 58 7f [2] 44 78 [2] 58 57 }

  condition:
    any of them
}