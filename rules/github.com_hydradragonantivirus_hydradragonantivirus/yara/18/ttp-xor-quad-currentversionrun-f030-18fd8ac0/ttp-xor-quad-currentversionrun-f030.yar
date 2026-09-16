rule TTP_XOR_QUAD_CurrentVersionRun_f030 {
  strings:
    $key_f030 = { a3 5f [2] 87 51 [2] ac 7d [2] 82 5f [2] 96 44 [2] 99 5e [2] 87 43 [2] 85 42 [2] 9e 44 [2] 82 43 [2] 9e 6c }

  condition:
    any of them
}