rule TTP_XOR_QUAD_CurrentVersionRun_54eb {
  strings:
    $key_54eb = { 07 84 [2] 23 8a [2] 08 a6 [2] 26 84 [2] 32 9f [2] 3d 85 [2] 23 98 [2] 21 99 [2] 3a 9f [2] 26 98 [2] 3a b7 }

  condition:
    any of them
}