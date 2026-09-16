rule TTP_XOR_QUAD_CurrentVersionRun_0517 {
  strings:
    $key_0517 = { 56 78 [2] 72 76 [2] 59 5a [2] 77 78 [2] 63 63 [2] 6c 79 [2] 72 64 [2] 70 65 [2] 6b 63 [2] 77 64 [2] 6b 4b }

  condition:
    any of them
}