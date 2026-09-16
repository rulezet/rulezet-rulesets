rule TTP_XOR_QUAD_CurrentVersionRun_feef {
  strings:
    $key_feef = { ad 80 [2] 89 8e [2] a2 a2 [2] 8c 80 [2] 98 9b [2] 97 81 [2] 89 9c [2] 8b 9d [2] 90 9b [2] 8c 9c [2] 90 b3 }

  condition:
    any of them
}