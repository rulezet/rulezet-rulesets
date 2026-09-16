rule TTP_XOR_QUAD_CurrentVersionRun_fc28 {
  strings:
    $key_fc28 = { af 47 [2] 8b 49 [2] a0 65 [2] 8e 47 [2] 9a 5c [2] 95 46 [2] 8b 5b [2] 89 5a [2] 92 5c [2] 8e 5b [2] 92 74 }

  condition:
    any of them
}