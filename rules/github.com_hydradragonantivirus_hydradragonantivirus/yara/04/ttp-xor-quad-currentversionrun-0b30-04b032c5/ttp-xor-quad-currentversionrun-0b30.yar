rule TTP_XOR_QUAD_CurrentVersionRun_0b30 {
  strings:
    $key_0b30 = { 58 5f [2] 7c 51 [2] 57 7d [2] 79 5f [2] 6d 44 [2] 62 5e [2] 7c 43 [2] 7e 42 [2] 65 44 [2] 79 43 [2] 65 6c }

  condition:
    any of them
}