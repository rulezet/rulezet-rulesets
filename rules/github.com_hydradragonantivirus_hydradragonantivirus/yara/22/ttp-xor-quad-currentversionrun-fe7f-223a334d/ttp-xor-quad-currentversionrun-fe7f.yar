rule TTP_XOR_QUAD_CurrentVersionRun_fe7f {
  strings:
    $key_fe7f = { ad 10 [2] 89 1e [2] a2 32 [2] 8c 10 [2] 98 0b [2] 97 11 [2] 89 0c [2] 8b 0d [2] 90 0b [2] 8c 0c [2] 90 23 }

  condition:
    any of them
}