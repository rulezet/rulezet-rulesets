rule TTP_XOR_QUAD_CurrentVersionRun_3761 {
  strings:
    $key_3761 = { 64 0e [2] 40 00 [2] 6b 2c [2] 45 0e [2] 51 15 [2] 5e 0f [2] 40 12 [2] 42 13 [2] 59 15 [2] 45 12 [2] 59 3d }

  condition:
    any of them
}