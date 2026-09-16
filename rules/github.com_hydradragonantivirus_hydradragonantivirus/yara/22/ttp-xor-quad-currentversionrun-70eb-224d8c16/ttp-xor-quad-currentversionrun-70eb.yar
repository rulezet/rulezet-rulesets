rule TTP_XOR_QUAD_CurrentVersionRun_70eb {
  strings:
    $key_70eb = { 23 84 [2] 07 8a [2] 2c a6 [2] 02 84 [2] 16 9f [2] 19 85 [2] 07 98 [2] 05 99 [2] 1e 9f [2] 02 98 [2] 1e b7 }

  condition:
    any of them
}