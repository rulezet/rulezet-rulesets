rule TTP_XOR_QUAD_CurrentVersionRun_fe5d {
  strings:
    $key_fe5d = { ad 32 [2] 89 3c [2] a2 10 [2] 8c 32 [2] 98 29 [2] 97 33 [2] 89 2e [2] 8b 2f [2] 90 29 [2] 8c 2e [2] 90 01 }

  condition:
    any of them
}