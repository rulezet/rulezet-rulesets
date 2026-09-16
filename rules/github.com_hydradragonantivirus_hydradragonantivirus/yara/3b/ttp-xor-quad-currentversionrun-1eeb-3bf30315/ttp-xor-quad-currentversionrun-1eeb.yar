rule TTP_XOR_QUAD_CurrentVersionRun_1eeb {
  strings:
    $key_1eeb = { 4d 84 [2] 69 8a [2] 42 a6 [2] 6c 84 [2] 78 9f [2] 77 85 [2] 69 98 [2] 6b 99 [2] 70 9f [2] 6c 98 [2] 70 b7 }

  condition:
    any of them
}