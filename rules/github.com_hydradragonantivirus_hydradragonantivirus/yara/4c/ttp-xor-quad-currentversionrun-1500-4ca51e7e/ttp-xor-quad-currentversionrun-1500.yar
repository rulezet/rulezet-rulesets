rule TTP_XOR_QUAD_CurrentVersionRun_1500 {
  strings:
    $key_1500 = { 46 6f [2] 62 61 [2] 49 4d [2] 67 6f [2] 73 74 [2] 7c 6e [2] 62 73 [2] 60 72 [2] 7b 74 [2] 67 73 [2] 7b 5c }

  condition:
    any of them
}