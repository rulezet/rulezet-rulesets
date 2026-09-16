rule TTP_XOR_QUAD_CurrentVersionRun_fe3e {
  strings:
    $key_fe3e = { ad 51 [2] 89 5f [2] a2 73 [2] 8c 51 [2] 98 4a [2] 97 50 [2] 89 4d [2] 8b 4c [2] 90 4a [2] 8c 4d [2] 90 62 }

  condition:
    any of them
}