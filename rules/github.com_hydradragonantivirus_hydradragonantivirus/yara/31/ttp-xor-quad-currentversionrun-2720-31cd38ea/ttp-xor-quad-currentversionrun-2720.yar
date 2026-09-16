rule TTP_XOR_QUAD_CurrentVersionRun_2720 {
  strings:
    $key_2720 = { 74 4f [2] 50 41 [2] 7b 6d [2] 55 4f [2] 41 54 [2] 4e 4e [2] 50 53 [2] 52 52 [2] 49 54 [2] 55 53 [2] 49 7c }

  condition:
    any of them
}