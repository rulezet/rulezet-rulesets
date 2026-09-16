rule TTP_XOR_QUAD_CurrentVersionRun_2d30 {
  strings:
    $key_2d30 = { 7e 5f [2] 5a 51 [2] 71 7d [2] 5f 5f [2] 4b 44 [2] 44 5e [2] 5a 43 [2] 58 42 [2] 43 44 [2] 5f 43 [2] 43 6c }

  condition:
    any of them
}