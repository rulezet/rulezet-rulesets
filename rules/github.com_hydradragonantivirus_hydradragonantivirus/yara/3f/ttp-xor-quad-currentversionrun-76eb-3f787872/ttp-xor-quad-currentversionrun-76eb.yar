rule TTP_XOR_QUAD_CurrentVersionRun_76eb {
  strings:
    $key_76eb = { 25 84 [2] 01 8a [2] 2a a6 [2] 04 84 [2] 10 9f [2] 1f 85 [2] 01 98 [2] 03 99 [2] 18 9f [2] 04 98 [2] 18 b7 }

  condition:
    any of them
}