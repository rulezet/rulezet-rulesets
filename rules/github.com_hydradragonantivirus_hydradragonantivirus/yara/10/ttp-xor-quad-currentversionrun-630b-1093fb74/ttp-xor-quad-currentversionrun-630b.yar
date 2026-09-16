rule TTP_XOR_QUAD_CurrentVersionRun_630b {
  strings:
    $key_630b = { 30 64 [2] 14 6a [2] 3f 46 [2] 11 64 [2] 05 7f [2] 0a 65 [2] 14 78 [2] 16 79 [2] 0d 7f [2] 11 78 [2] 0d 57 }

  condition:
    any of them
}