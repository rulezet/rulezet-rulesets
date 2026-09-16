rule TTP_XOR_QUAD_CurrentVersionRun_fe73 {
  strings:
    $key_fe73 = { ad 1c [2] 89 12 [2] a2 3e [2] 8c 1c [2] 98 07 [2] 97 1d [2] 89 00 [2] 8b 01 [2] 90 07 [2] 8c 00 [2] 90 2f }

  condition:
    any of them
}