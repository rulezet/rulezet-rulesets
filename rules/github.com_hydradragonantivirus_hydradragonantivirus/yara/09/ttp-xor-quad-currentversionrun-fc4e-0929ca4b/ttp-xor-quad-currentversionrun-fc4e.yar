rule TTP_XOR_QUAD_CurrentVersionRun_fc4e {
  strings:
    $key_fc4e = { af 21 [2] 8b 2f [2] a0 03 [2] 8e 21 [2] 9a 3a [2] 95 20 [2] 8b 3d [2] 89 3c [2] 92 3a [2] 8e 3d [2] 92 12 }

  condition:
    any of them
}