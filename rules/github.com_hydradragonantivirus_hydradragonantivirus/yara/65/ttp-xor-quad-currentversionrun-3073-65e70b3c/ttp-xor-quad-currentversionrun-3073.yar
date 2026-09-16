rule TTP_XOR_QUAD_CurrentVersionRun_3073 {
  strings:
    $key_3073 = { 63 1c [2] 47 12 [2] 6c 3e [2] 42 1c [2] 56 07 [2] 59 1d [2] 47 00 [2] 45 01 [2] 5e 07 [2] 42 00 [2] 5e 2f }

  condition:
    any of them
}