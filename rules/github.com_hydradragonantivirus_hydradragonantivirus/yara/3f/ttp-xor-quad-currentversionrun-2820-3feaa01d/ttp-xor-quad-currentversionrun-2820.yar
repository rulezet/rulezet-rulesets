rule TTP_XOR_QUAD_CurrentVersionRun_2820 {
  strings:
    $key_2820 = { 7b 4f [2] 5f 41 [2] 74 6d [2] 5a 4f [2] 4e 54 [2] 41 4e [2] 5f 53 [2] 5d 52 [2] 46 54 [2] 5a 53 [2] 46 7c }

  condition:
    any of them
}