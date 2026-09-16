rule TTP_XOR_QUAD_CurrentVersionRun_fe77 {
  strings:
    $key_fe77 = { ad 18 [2] 89 16 [2] a2 3a [2] 8c 18 [2] 98 03 [2] 97 19 [2] 89 04 [2] 8b 05 [2] 90 03 [2] 8c 04 [2] 90 2b }

  condition:
    any of them
}