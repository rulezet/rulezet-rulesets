rule TTP_XOR_QUAD_CurrentVersionRun_fe5c {
  strings:
    $key_fe5c = { ad 33 [2] 89 3d [2] a2 11 [2] 8c 33 [2] 98 28 [2] 97 32 [2] 89 2f [2] 8b 2e [2] 90 28 [2] 8c 2f [2] 90 00 }

  condition:
    any of them
}