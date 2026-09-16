rule TTP_XOR_QUAD_CurrentVersionRun_3620 {
  strings:
    $key_3620 = { 65 4f [2] 41 41 [2] 6a 6d [2] 44 4f [2] 50 54 [2] 5f 4e [2] 41 53 [2] 43 52 [2] 58 54 [2] 44 53 [2] 58 7c }

  condition:
    any of them
}