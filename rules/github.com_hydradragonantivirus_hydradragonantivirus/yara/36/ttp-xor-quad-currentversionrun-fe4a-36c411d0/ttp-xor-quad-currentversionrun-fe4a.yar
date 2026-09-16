rule TTP_XOR_QUAD_CurrentVersionRun_fe4a {
  strings:
    $key_fe4a = { ad 25 [2] 89 2b [2] a2 07 [2] 8c 25 [2] 98 3e [2] 97 24 [2] 89 39 [2] 8b 38 [2] 90 3e [2] 8c 39 [2] 90 16 }

  condition:
    any of them
}