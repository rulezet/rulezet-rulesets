rule TTP_XOR_QUAD_CurrentVersionRun_4b00 {
  strings:
    $key_4b00 = { 18 6f [2] 3c 61 [2] 17 4d [2] 39 6f [2] 2d 74 [2] 22 6e [2] 3c 73 [2] 3e 72 [2] 25 74 [2] 39 73 [2] 25 5c }

  condition:
    any of them
}