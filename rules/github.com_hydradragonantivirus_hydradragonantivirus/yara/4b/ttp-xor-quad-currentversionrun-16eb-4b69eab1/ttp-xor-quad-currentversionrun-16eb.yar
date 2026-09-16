rule TTP_XOR_QUAD_CurrentVersionRun_16eb {
  strings:
    $key_16eb = { 45 84 [2] 61 8a [2] 4a a6 [2] 64 84 [2] 70 9f [2] 7f 85 [2] 61 98 [2] 63 99 [2] 78 9f [2] 64 98 [2] 78 b7 }

  condition:
    any of them
}