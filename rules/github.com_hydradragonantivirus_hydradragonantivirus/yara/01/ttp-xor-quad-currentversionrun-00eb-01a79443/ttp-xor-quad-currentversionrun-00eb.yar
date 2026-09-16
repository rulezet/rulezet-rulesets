rule TTP_XOR_QUAD_CurrentVersionRun_00eb {
  strings:
    $key_00eb = { 53 84 [2] 77 8a [2] 5c a6 [2] 72 84 [2] 66 9f [2] 69 85 [2] 77 98 [2] 75 99 [2] 6e 9f [2] 72 98 [2] 6e b7 }

  condition:
    any of them
}