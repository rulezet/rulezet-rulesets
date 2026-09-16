rule TTP_XOR_QUAD_CurrentVersionRun_385b {
  strings:
    $key_385b = { 6b 34 [2] 4f 3a [2] 64 16 [2] 4a 34 [2] 5e 2f [2] 51 35 [2] 4f 28 [2] 4d 29 [2] 56 2f [2] 4a 28 [2] 56 07 }

  condition:
    any of them
}