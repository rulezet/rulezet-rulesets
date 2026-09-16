rule TTP_XOR_QUAD_CurrentVersionRun_fc5f {
  strings:
    $key_fc5f = { af 30 [2] 8b 3e [2] a0 12 [2] 8e 30 [2] 9a 2b [2] 95 31 [2] 8b 2c [2] 89 2d [2] 92 2b [2] 8e 2c [2] 92 03 }

  condition:
    any of them
}