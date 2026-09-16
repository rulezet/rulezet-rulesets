rule TTP_XOR_QUAD_CurrentVersionRun_fe67 {
  strings:
    $key_fe67 = { ad 08 [2] 89 06 [2] a2 2a [2] 8c 08 [2] 98 13 [2] 97 09 [2] 89 14 [2] 8b 15 [2] 90 13 [2] 8c 14 [2] 90 3b }

  condition:
    any of them
}