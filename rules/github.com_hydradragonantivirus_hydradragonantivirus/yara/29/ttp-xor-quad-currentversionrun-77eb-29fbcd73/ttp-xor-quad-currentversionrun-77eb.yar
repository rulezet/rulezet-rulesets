rule TTP_XOR_QUAD_CurrentVersionRun_77eb {
  strings:
    $key_77eb = { 24 84 [2] 00 8a [2] 2b a6 [2] 05 84 [2] 11 9f [2] 1e 85 [2] 00 98 [2] 02 99 [2] 19 9f [2] 05 98 [2] 19 b7 }

  condition:
    any of them
}