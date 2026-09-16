rule TTP_XOR_QUAD_CurrentVersionRun_0d0b {
  strings:
    $key_0d0b = { 5e 64 [2] 7a 6a [2] 51 46 [2] 7f 64 [2] 6b 7f [2] 64 65 [2] 7a 78 [2] 78 79 [2] 63 7f [2] 7f 78 [2] 63 57 }

  condition:
    any of them
}