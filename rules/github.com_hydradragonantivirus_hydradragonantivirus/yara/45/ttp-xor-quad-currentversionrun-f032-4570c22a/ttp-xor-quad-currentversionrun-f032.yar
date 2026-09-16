rule TTP_XOR_QUAD_CurrentVersionRun_f032 {
  strings:
    $key_f032 = { a3 5d [2] 87 53 [2] ac 7f [2] 82 5d [2] 96 46 [2] 99 5c [2] 87 41 [2] 85 40 [2] 9e 46 [2] 82 41 [2] 9e 6e }

  condition:
    any of them
}