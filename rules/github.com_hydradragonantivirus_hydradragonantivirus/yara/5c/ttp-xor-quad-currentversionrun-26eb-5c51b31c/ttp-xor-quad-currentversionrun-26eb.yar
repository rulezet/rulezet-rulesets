rule TTP_XOR_QUAD_CurrentVersionRun_26eb {
  strings:
    $key_26eb = { 75 84 [2] 51 8a [2] 7a a6 [2] 54 84 [2] 40 9f [2] 4f 85 [2] 51 98 [2] 53 99 [2] 48 9f [2] 54 98 [2] 48 b7 }

  condition:
    any of them
}