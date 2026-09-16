rule TTP_XOR_QUAD_CurrentVersionRun_2d20 {
  strings:
    $key_2d20 = { 7e 4f [2] 5a 41 [2] 71 6d [2] 5f 4f [2] 4b 54 [2] 44 4e [2] 5a 53 [2] 58 52 [2] 43 54 [2] 5f 53 [2] 43 7c }

  condition:
    any of them
}