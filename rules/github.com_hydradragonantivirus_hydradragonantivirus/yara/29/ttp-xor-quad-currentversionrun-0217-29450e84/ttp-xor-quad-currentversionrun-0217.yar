rule TTP_XOR_QUAD_CurrentVersionRun_0217 {
  strings:
    $key_0217 = { 51 78 [2] 75 76 [2] 5e 5a [2] 70 78 [2] 64 63 [2] 6b 79 [2] 75 64 [2] 77 65 [2] 6c 63 [2] 70 64 [2] 6c 4b }

  condition:
    any of them
}