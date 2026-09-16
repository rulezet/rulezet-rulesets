rule TTP_XOR_QUAD_CurrentVersionRun_3746 {
  strings:
    $key_3746 = { 64 29 [2] 40 27 [2] 6b 0b [2] 45 29 [2] 51 32 [2] 5e 28 [2] 40 35 [2] 42 34 [2] 59 32 [2] 45 35 [2] 59 1a }

  condition:
    any of them
}