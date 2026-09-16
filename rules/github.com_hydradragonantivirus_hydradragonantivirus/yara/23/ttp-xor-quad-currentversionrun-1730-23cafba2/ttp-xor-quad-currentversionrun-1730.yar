rule TTP_XOR_QUAD_CurrentVersionRun_1730 {
  strings:
    $key_1730 = { 44 5f [2] 60 51 [2] 4b 7d [2] 65 5f [2] 71 44 [2] 7e 5e [2] 60 43 [2] 62 42 [2] 79 44 [2] 65 43 [2] 79 6c }

  condition:
    any of them
}