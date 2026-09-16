rule TTP_XOR_QUAD_CurrentVersionRun_feee {
  strings:
    $key_feee = { ad 81 [2] 89 8f [2] a2 a3 [2] 8c 81 [2] 98 9a [2] 97 80 [2] 89 9d [2] 8b 9c [2] 90 9a [2] 8c 9d [2] 90 b2 }

  condition:
    any of them
}