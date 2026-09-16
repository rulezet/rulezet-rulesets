rule TTP_XOR_QUAD_CurrentVersionRun_fc01 {
  strings:
    $key_fc01 = { af 6e [2] 8b 60 [2] a0 4c [2] 8e 6e [2] 9a 75 [2] 95 6f [2] 8b 72 [2] 89 73 [2] 92 75 [2] 8e 72 [2] 92 5d }

  condition:
    any of them
}