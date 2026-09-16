rule TTP_XOR_QUAD_CurrentVersionRun_080b {
  strings:
    $key_080b = { 5b 64 [2] 7f 6a [2] 54 46 [2] 7a 64 [2] 6e 7f [2] 61 65 [2] 7f 78 [2] 7d 79 [2] 66 7f [2] 7a 78 [2] 66 57 }

  condition:
    any of them
}