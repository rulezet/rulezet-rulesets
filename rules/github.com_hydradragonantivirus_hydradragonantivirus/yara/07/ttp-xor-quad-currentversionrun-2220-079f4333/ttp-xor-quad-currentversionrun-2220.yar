rule TTP_XOR_QUAD_CurrentVersionRun_2220 {
  strings:
    $key_2220 = { 71 4f [2] 55 41 [2] 7e 6d [2] 50 4f [2] 44 54 [2] 4b 4e [2] 55 53 [2] 57 52 [2] 4c 54 [2] 50 53 [2] 4c 7c }

  condition:
    any of them
}