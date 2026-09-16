rule TTP_XOR_QUAD_CurrentVersionRun_0a0b {
  strings:
    $key_0a0b = { 59 64 [2] 7d 6a [2] 56 46 [2] 78 64 [2] 6c 7f [2] 63 65 [2] 7d 78 [2] 7f 79 [2] 64 7f [2] 78 78 [2] 64 57 }

  condition:
    any of them
}