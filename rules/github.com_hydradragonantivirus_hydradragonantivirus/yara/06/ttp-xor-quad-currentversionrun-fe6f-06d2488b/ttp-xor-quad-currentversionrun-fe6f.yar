rule TTP_XOR_QUAD_CurrentVersionRun_fe6f {
  strings:
    $key_fe6f = { ad 00 [2] 89 0e [2] a2 22 [2] 8c 00 [2] 98 1b [2] 97 01 [2] 89 1c [2] 8b 1d [2] 90 1b [2] 8c 1c [2] 90 33 }

  condition:
    any of them
}