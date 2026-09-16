rule TTP_XOR_QUAD_CurrentVersionRun_6200 {
  strings:
    $key_6200 = { 31 6f [2] 15 61 [2] 3e 4d [2] 10 6f [2] 04 74 [2] 0b 6e [2] 15 73 [2] 17 72 [2] 0c 74 [2] 10 73 [2] 0c 5c }

  condition:
    any of them
}