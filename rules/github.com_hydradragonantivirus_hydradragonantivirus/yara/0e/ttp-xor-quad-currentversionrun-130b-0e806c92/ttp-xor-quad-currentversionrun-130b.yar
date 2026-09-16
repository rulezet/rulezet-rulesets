rule TTP_XOR_QUAD_CurrentVersionRun_130b {
  strings:
    $key_130b = { 40 64 [2] 64 6a [2] 4f 46 [2] 61 64 [2] 75 7f [2] 7a 65 [2] 64 78 [2] 66 79 [2] 7d 7f [2] 61 78 [2] 7d 57 }

  condition:
    any of them
}