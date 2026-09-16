rule TTP_XOR_QUAD_CurrentVersionRun_fe6e {
  strings:
    $key_fe6e = { ad 01 [2] 89 0f [2] a2 23 [2] 8c 01 [2] 98 1a [2] 97 00 [2] 89 1d [2] 8b 1c [2] 90 1a [2] 8c 1d [2] 90 32 }

  condition:
    any of them
}