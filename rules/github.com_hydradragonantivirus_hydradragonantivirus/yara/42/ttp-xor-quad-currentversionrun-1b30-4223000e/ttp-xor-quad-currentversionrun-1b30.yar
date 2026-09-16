rule TTP_XOR_QUAD_CurrentVersionRun_1b30 {
  strings:
    $key_1b30 = { 48 5f [2] 6c 51 [2] 47 7d [2] 69 5f [2] 7d 44 [2] 72 5e [2] 6c 43 [2] 6e 42 [2] 75 44 [2] 69 43 [2] 75 6c }

  condition:
    any of them
}