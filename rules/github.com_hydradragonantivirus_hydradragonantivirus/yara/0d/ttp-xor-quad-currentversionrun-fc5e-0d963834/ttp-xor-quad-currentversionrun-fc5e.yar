rule TTP_XOR_QUAD_CurrentVersionRun_fc5e {
  strings:
    $key_fc5e = { af 31 [2] 8b 3f [2] a0 13 [2] 8e 31 [2] 9a 2a [2] 95 30 [2] 8b 2d [2] 89 2c [2] 92 2a [2] 8e 2d [2] 92 02 }

  condition:
    any of them
}