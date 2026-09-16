rule TTP_XOR_QUAD_CurrentVersionRun_fc3b {
  strings:
    $key_fc3b = { af 54 [2] 8b 5a [2] a0 76 [2] 8e 54 [2] 9a 4f [2] 95 55 [2] 8b 48 [2] 89 49 [2] 92 4f [2] 8e 48 [2] 92 67 }

  condition:
    any of them
}