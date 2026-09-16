rule TTP_XOR_QUAD_CurrentVersionRun_fc11 {
  strings:
    $key_fc11 = { af 7e [2] 8b 70 [2] a0 5c [2] 8e 7e [2] 9a 65 [2] 95 7f [2] 8b 62 [2] 89 63 [2] 92 65 [2] 8e 62 [2] 92 4d }

  condition:
    any of them
}