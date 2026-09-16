rule TTP_XOR_QUAD_CurrentVersionRun_0546 {
  strings:
    $key_0546 = { 56 29 [2] 72 27 [2] 59 0b [2] 77 29 [2] 63 32 [2] 6c 28 [2] 72 35 [2] 70 34 [2] 6b 32 [2] 77 35 [2] 6b 1a }

  condition:
    any of them
}