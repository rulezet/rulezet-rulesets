rule TTP_XOR_QUAD_CurrentVersionRun_fe23 {
  strings:
    $key_fe23 = { ad 4c [2] 89 42 [2] a2 6e [2] 8c 4c [2] 98 57 [2] 97 4d [2] 89 50 [2] 8b 51 [2] 90 57 [2] 8c 50 [2] 90 7f }

  condition:
    any of them
}