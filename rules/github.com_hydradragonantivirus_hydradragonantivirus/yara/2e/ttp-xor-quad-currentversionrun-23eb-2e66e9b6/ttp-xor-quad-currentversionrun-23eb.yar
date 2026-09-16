rule TTP_XOR_QUAD_CurrentVersionRun_23eb {
  strings:
    $key_23eb = { 70 84 [2] 54 8a [2] 7f a6 [2] 51 84 [2] 45 9f [2] 4a 85 [2] 54 98 [2] 56 99 [2] 4d 9f [2] 51 98 [2] 4d b7 }

  condition:
    any of them
}