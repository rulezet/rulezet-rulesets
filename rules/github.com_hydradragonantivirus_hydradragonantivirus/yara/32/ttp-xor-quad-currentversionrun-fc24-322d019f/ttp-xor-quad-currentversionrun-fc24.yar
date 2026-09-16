rule TTP_XOR_QUAD_CurrentVersionRun_fc24 {
  strings:
    $key_fc24 = { af 4b [2] 8b 45 [2] a0 69 [2] 8e 4b [2] 9a 50 [2] 95 4a [2] 8b 57 [2] 89 56 [2] 92 50 [2] 8e 57 [2] 92 78 }

  condition:
    any of them
}