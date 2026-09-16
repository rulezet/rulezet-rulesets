rule TTP_XOR_QUAD_CurrentVersionRun_5800 {
  strings:
    $key_5800 = { 0b 6f [2] 2f 61 [2] 04 4d [2] 2a 6f [2] 3e 74 [2] 31 6e [2] 2f 73 [2] 2d 72 [2] 36 74 [2] 2a 73 [2] 36 5c }

  condition:
    any of them
}