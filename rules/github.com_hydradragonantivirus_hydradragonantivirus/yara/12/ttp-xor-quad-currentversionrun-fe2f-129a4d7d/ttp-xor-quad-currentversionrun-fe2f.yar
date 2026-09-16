rule TTP_XOR_QUAD_CurrentVersionRun_fe2f {
  strings:
    $key_fe2f = { ad 40 [2] 89 4e [2] a2 62 [2] 8c 40 [2] 98 5b [2] 97 41 [2] 89 5c [2] 8b 5d [2] 90 5b [2] 8c 5c [2] 90 73 }

  condition:
    any of them
}