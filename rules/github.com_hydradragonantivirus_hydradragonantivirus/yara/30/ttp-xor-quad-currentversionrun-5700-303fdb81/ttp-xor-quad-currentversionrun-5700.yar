rule TTP_XOR_QUAD_CurrentVersionRun_5700 {
  strings:
    $key_5700 = { 04 6f [2] 20 61 [2] 0b 4d [2] 25 6f [2] 31 74 [2] 3e 6e [2] 20 73 [2] 22 72 [2] 39 74 [2] 25 73 [2] 39 5c }

  condition:
    any of them
}