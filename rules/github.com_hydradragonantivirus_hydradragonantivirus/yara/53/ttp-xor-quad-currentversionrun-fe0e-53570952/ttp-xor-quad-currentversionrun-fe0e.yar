rule TTP_XOR_QUAD_CurrentVersionRun_fe0e {
  strings:
    $key_fe0e = { ad 61 [2] 89 6f [2] a2 43 [2] 8c 61 [2] 98 7a [2] 97 60 [2] 89 7d [2] 8b 7c [2] 90 7a [2] 8c 7d [2] 90 52 }

  condition:
    any of them
}