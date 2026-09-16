rule TTP_XOR_QUAD_CurrentVersionRun_6240 {
  strings:
    $key_6240 = { 31 2f [2] 15 21 [2] 3e 0d [2] 10 2f [2] 04 34 [2] 0b 2e [2] 15 33 [2] 17 32 [2] 0c 34 [2] 10 33 [2] 0c 1c }

  condition:
    any of them
}