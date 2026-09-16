rule TTP_XOR_QUAD_CurrentVersionRun_fc02 {
  strings:
    $key_fc02 = { af 6d [2] 8b 63 [2] a0 4f [2] 8e 6d [2] 9a 76 [2] 95 6c [2] 8b 71 [2] 89 70 [2] 92 76 [2] 8e 71 [2] 92 5e }

  condition:
    any of them
}