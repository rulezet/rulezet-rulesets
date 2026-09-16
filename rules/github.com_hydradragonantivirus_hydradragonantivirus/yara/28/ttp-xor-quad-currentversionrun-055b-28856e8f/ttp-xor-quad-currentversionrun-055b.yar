rule TTP_XOR_QUAD_CurrentVersionRun_055b {
  strings:
    $key_055b = { 56 34 [2] 72 3a [2] 59 16 [2] 77 34 [2] 63 2f [2] 6c 35 [2] 72 28 [2] 70 29 [2] 6b 2f [2] 77 28 [2] 6b 07 }

  condition:
    any of them
}