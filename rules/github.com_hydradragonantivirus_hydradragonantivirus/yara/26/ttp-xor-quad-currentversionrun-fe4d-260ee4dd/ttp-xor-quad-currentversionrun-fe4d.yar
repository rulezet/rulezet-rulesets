rule TTP_XOR_QUAD_CurrentVersionRun_fe4d {
  strings:
    $key_fe4d = { ad 22 [2] 89 2c [2] a2 00 [2] 8c 22 [2] 98 39 [2] 97 23 [2] 89 3e [2] 8b 3f [2] 90 39 [2] 8c 3e [2] 90 11 }

  condition:
    any of them
}