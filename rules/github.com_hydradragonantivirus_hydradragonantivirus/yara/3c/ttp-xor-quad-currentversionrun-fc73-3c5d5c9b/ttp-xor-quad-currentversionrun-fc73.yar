rule TTP_XOR_QUAD_CurrentVersionRun_fc73 {
  strings:
    $key_fc73 = { af 1c [2] 8b 12 [2] a0 3e [2] 8e 1c [2] 9a 07 [2] 95 1d [2] 8b 00 [2] 89 01 [2] 92 07 [2] 8e 00 [2] 92 2f }

  condition:
    any of them
}