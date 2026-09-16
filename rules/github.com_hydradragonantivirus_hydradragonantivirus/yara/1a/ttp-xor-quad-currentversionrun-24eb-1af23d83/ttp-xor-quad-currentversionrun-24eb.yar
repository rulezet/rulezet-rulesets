rule TTP_XOR_QUAD_CurrentVersionRun_24eb {
  strings:
    $key_24eb = { 77 84 [2] 53 8a [2] 78 a6 [2] 56 84 [2] 42 9f [2] 4d 85 [2] 53 98 [2] 51 99 [2] 4a 9f [2] 56 98 [2] 4a b7 }

  condition:
    any of them
}