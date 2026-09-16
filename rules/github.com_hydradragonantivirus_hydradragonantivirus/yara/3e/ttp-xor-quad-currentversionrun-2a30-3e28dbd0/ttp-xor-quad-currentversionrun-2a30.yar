rule TTP_XOR_QUAD_CurrentVersionRun_2a30 {
  strings:
    $key_2a30 = { 79 5f [2] 5d 51 [2] 76 7d [2] 58 5f [2] 4c 44 [2] 43 5e [2] 5d 43 [2] 5f 42 [2] 44 44 [2] 58 43 [2] 44 6c }

  condition:
    any of them
}