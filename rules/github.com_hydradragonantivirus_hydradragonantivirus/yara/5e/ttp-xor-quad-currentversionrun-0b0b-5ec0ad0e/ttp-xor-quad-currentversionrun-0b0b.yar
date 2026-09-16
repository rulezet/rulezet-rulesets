rule TTP_XOR_QUAD_CurrentVersionRun_0b0b {
  strings:
    $key_0b0b = { 58 64 [2] 7c 6a [2] 57 46 [2] 79 64 [2] 6d 7f [2] 62 65 [2] 7c 78 [2] 7e 79 [2] 65 7f [2] 79 78 [2] 65 57 }

  condition:
    any of them
}