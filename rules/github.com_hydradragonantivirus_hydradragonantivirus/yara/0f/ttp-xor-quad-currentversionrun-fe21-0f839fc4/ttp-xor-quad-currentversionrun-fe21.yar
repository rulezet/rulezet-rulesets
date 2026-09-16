rule TTP_XOR_QUAD_CurrentVersionRun_fe21 {
  strings:
    $key_fe21 = { ad 4e [2] 89 40 [2] a2 6c [2] 8c 4e [2] 98 55 [2] 97 4f [2] 89 52 [2] 8b 53 [2] 90 55 [2] 8c 52 [2] 90 7d }

  condition:
    any of them
}