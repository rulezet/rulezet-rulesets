rule TTP_XOR_QUAD_CurrentVersionRun_230b {
  strings:
    $key_230b = { 70 64 [2] 54 6a [2] 7f 46 [2] 51 64 [2] 45 7f [2] 4a 65 [2] 54 78 [2] 56 79 [2] 4d 7f [2] 51 78 [2] 4d 57 }

  condition:
    any of them
}