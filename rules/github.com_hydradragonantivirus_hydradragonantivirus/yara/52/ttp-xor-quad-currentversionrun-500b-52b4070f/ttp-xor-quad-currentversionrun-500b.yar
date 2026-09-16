rule TTP_XOR_QUAD_CurrentVersionRun_500b {
  strings:
    $key_500b = { 03 64 [2] 27 6a [2] 0c 46 [2] 22 64 [2] 36 7f [2] 39 65 [2] 27 78 [2] 25 79 [2] 3e 7f [2] 22 78 [2] 3e 57 }

  condition:
    any of them
}