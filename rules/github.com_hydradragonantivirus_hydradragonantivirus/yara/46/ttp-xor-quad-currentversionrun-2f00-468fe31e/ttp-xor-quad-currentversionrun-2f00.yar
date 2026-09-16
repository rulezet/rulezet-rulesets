rule TTP_XOR_QUAD_CurrentVersionRun_2f00 {
  strings:
    $key_2f00 = { 7c 6f [2] 58 61 [2] 73 4d [2] 5d 6f [2] 49 74 [2] 46 6e [2] 58 73 [2] 5a 72 [2] 41 74 [2] 5d 73 [2] 41 5c }

  condition:
    any of them
}