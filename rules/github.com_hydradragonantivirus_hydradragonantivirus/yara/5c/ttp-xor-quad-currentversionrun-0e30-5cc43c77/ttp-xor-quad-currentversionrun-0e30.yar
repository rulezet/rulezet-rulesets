rule TTP_XOR_QUAD_CurrentVersionRun_0e30 {
  strings:
    $key_0e30 = { 5d 5f [2] 79 51 [2] 52 7d [2] 7c 5f [2] 68 44 [2] 67 5e [2] 79 43 [2] 7b 42 [2] 60 44 [2] 7c 43 [2] 60 6c }

  condition:
    any of them
}