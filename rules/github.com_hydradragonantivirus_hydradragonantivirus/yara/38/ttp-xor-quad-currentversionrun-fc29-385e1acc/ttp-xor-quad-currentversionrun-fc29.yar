rule TTP_XOR_QUAD_CurrentVersionRun_fc29 {
  strings:
    $key_fc29 = { af 46 [2] 8b 48 [2] a0 64 [2] 8e 46 [2] 9a 5d [2] 95 47 [2] 8b 5a [2] 89 5b [2] 92 5d [2] 8e 5a [2] 92 75 }

  condition:
    any of them
}