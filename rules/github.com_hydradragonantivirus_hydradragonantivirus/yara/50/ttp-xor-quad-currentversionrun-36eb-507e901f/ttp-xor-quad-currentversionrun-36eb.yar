rule TTP_XOR_QUAD_CurrentVersionRun_36eb {
  strings:
    $key_36eb = { 65 84 [2] 41 8a [2] 6a a6 [2] 44 84 [2] 50 9f [2] 5f 85 [2] 41 98 [2] 43 99 [2] 58 9f [2] 44 98 [2] 58 b7 }

  condition:
    any of them
}