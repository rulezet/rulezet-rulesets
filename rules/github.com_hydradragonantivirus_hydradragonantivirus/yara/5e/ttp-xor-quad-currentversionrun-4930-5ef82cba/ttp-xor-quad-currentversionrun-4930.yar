rule TTP_XOR_QUAD_CurrentVersionRun_4930 {
  strings:
    $key_4930 = { 1a 5f [2] 3e 51 [2] 15 7d [2] 3b 5f [2] 2f 44 [2] 20 5e [2] 3e 43 [2] 3c 42 [2] 27 44 [2] 3b 43 [2] 27 6c }

  condition:
    any of them
}