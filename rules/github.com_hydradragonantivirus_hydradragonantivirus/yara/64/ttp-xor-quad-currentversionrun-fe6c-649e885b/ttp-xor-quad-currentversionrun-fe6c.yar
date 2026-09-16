rule TTP_XOR_QUAD_CurrentVersionRun_fe6c {
  strings:
    $key_fe6c = { ad 03 [2] 89 0d [2] a2 21 [2] 8c 03 [2] 98 18 [2] 97 02 [2] 89 1f [2] 8b 1e [2] 90 18 [2] 8c 1f [2] 90 30 }

  condition:
    any of them
}