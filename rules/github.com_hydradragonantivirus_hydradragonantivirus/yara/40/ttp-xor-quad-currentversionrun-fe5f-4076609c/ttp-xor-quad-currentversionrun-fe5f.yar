rule TTP_XOR_QUAD_CurrentVersionRun_fe5f {
  strings:
    $key_fe5f = { ad 30 [2] 89 3e [2] a2 12 [2] 8c 30 [2] 98 2b [2] 97 31 [2] 89 2c [2] 8b 2d [2] 90 2b [2] 8c 2c [2] 90 03 }

  condition:
    any of them
}