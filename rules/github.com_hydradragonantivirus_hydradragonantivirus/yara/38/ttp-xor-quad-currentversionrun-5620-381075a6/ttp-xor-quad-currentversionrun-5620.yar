rule TTP_XOR_QUAD_CurrentVersionRun_5620 {
  strings:
    $key_5620 = { 05 4f [2] 21 41 [2] 0a 6d [2] 24 4f [2] 30 54 [2] 3f 4e [2] 21 53 [2] 23 52 [2] 38 54 [2] 24 53 [2] 38 7c }

  condition:
    any of them
}