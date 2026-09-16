rule TTP_XOR_QUAD_CurrentVersionRun_5530 {
  strings:
    $key_5530 = { 06 5f [2] 22 51 [2] 09 7d [2] 27 5f [2] 33 44 [2] 3c 5e [2] 22 43 [2] 20 42 [2] 3b 44 [2] 27 43 [2] 3b 6c }

  condition:
    any of them
}