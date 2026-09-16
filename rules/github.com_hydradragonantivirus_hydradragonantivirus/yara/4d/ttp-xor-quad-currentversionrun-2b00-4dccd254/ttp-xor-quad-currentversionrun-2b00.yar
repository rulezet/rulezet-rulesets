rule TTP_XOR_QUAD_CurrentVersionRun_2b00 {
  strings:
    $key_2b00 = { 78 6f [2] 5c 61 [2] 77 4d [2] 59 6f [2] 4d 74 [2] 42 6e [2] 5c 73 [2] 5e 72 [2] 45 74 [2] 59 73 [2] 45 5c }

  condition:
    any of them
}