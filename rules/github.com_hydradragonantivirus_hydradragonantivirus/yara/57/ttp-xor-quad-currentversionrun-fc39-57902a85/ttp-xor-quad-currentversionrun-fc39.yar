rule TTP_XOR_QUAD_CurrentVersionRun_fc39 {
  strings:
    $key_fc39 = { af 56 [2] 8b 58 [2] a0 74 [2] 8e 56 [2] 9a 4d [2] 95 57 [2] 8b 4a [2] 89 4b [2] 92 4d [2] 8e 4a [2] 92 65 }

  condition:
    any of them
}