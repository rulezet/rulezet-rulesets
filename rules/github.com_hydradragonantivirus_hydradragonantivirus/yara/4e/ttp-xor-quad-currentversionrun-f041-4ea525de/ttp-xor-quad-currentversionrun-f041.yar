rule TTP_XOR_QUAD_CurrentVersionRun_f041 {
  strings:
    $key_f041 = { a3 2e [2] 87 20 [2] ac 0c [2] 82 2e [2] 96 35 [2] 99 2f [2] 87 32 [2] 85 33 [2] 9e 35 [2] 82 32 [2] 9e 1d }

  condition:
    any of them
}