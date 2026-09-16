rule TTP_XOR_QUAD_CurrentVersionRun_1beb {
  strings:
    $key_1beb = { 48 84 [2] 6c 8a [2] 47 a6 [2] 69 84 [2] 7d 9f [2] 72 85 [2] 6c 98 [2] 6e 99 [2] 75 9f [2] 69 98 [2] 75 b7 }

  condition:
    any of them
}