rule TTP_XOR_QUAD_CurrentVersionRun_fc4b {
  strings:
    $key_fc4b = { af 24 [2] 8b 2a [2] a0 06 [2] 8e 24 [2] 9a 3f [2] 95 25 [2] 8b 38 [2] 89 39 [2] 92 3f [2] 8e 38 [2] 92 17 }

  condition:
    any of them
}