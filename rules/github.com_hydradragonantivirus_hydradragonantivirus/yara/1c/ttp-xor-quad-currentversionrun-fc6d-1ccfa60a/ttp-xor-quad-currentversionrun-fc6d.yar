rule TTP_XOR_QUAD_CurrentVersionRun_fc6d {
  strings:
    $key_fc6d = { af 02 [2] 8b 0c [2] a0 20 [2] 8e 02 [2] 9a 19 [2] 95 03 [2] 8b 1e [2] 89 1f [2] 92 19 [2] 8e 1e [2] 92 31 }

  condition:
    any of them
}