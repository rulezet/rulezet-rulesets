rule TTP_XOR_QUAD_CurrentVersionRun_6530 {
  strings:
    $key_6530 = { 36 5f [2] 12 51 [2] 39 7d [2] 17 5f [2] 03 44 [2] 0c 5e [2] 12 43 [2] 10 42 [2] 0b 44 [2] 17 43 [2] 0b 6c }

  condition:
    any of them
}