rule TTP_XOR_QUAD_CurrentVersionRun_fc6e {
  strings:
    $key_fc6e = { af 01 [2] 8b 0f [2] a0 23 [2] 8e 01 [2] 9a 1a [2] 95 00 [2] 8b 1d [2] 89 1c [2] 92 1a [2] 8e 1d [2] 92 32 }

  condition:
    any of them
}