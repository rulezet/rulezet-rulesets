rule TTP_XOR_QUAD_CurrentVersionRun_fc60 {
  strings:
    $key_fc60 = { af 0f [2] 8b 01 [2] a0 2d [2] 8e 0f [2] 9a 14 [2] 95 0e [2] 8b 13 [2] 89 12 [2] 92 14 [2] 8e 13 [2] 92 3c }

  condition:
    any of them
}