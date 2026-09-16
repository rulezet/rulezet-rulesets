rule TTP_XOR_QUAD_CurrentVersionRun_fe7d {
  strings:
    $key_fe7d = { ad 12 [2] 89 1c [2] a2 30 [2] 8c 12 [2] 98 09 [2] 97 13 [2] 89 0e [2] 8b 0f [2] 90 09 [2] 8c 0e [2] 90 21 }

  condition:
    any of them
}