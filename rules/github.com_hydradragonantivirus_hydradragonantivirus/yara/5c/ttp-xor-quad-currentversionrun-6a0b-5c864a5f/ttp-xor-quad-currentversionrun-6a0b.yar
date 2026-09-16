rule TTP_XOR_QUAD_CurrentVersionRun_6a0b {
  strings:
    $key_6a0b = { 39 64 [2] 1d 6a [2] 36 46 [2] 18 64 [2] 0c 7f [2] 03 65 [2] 1d 78 [2] 1f 79 [2] 04 7f [2] 18 78 [2] 04 57 }

  condition:
    any of them
}