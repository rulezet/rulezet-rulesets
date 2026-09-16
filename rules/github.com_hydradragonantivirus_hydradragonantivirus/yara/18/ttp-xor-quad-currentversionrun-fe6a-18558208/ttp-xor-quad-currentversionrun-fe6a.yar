rule TTP_XOR_QUAD_CurrentVersionRun_fe6a {
  strings:
    $key_fe6a = { ad 05 [2] 89 0b [2] a2 27 [2] 8c 05 [2] 98 1e [2] 97 04 [2] 89 19 [2] 8b 18 [2] 90 1e [2] 8c 19 [2] 90 36 }

  condition:
    any of them
}