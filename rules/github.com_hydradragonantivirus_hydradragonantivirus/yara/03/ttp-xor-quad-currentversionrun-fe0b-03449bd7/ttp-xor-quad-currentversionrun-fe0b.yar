rule TTP_XOR_QUAD_CurrentVersionRun_fe0b {
  strings:
    $key_fe0b = { ad 64 [2] 89 6a [2] a2 46 [2] 8c 64 [2] 98 7f [2] 97 65 [2] 89 78 [2] 8b 79 [2] 90 7f [2] 8c 78 [2] 90 57 }

  condition:
    any of them
}