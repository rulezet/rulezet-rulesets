rule TTP_XOR_QUAD_CurrentVersionRun_fc6a {
  strings:
    $key_fc6a = { af 05 [2] 8b 0b [2] a0 27 [2] 8e 05 [2] 9a 1e [2] 95 04 [2] 8b 19 [2] 89 18 [2] 92 1e [2] 8e 19 [2] 92 36 }

  condition:
    any of them
}