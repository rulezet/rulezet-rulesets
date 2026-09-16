rule TTP_XOR_QUAD_CurrentVersionRun_fc26 {
  strings:
    $key_fc26 = { af 49 [2] 8b 47 [2] a0 6b [2] 8e 49 [2] 9a 52 [2] 95 48 [2] 8b 55 [2] 89 54 [2] 92 52 [2] 8e 55 [2] 92 7a }

  condition:
    any of them
}