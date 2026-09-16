rule TTP_XOR_QUAD_CurrentVersionRun_4d54 {
  strings:
    $key_4d54 = { 1e 3b [2] 3a 35 [2] 11 19 [2] 3f 3b [2] 2b 20 [2] 24 3a [2] 3a 27 [2] 38 26 [2] 23 20 [2] 3f 27 [2] 23 08 }

  condition:
    any of them
}