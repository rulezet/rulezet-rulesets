rule TTP_XOR_QUAD_CurrentVersionRun_f02a {
  strings:
    $key_f02a = { a3 45 [2] 87 4b [2] ac 67 [2] 82 45 [2] 96 5e [2] 99 44 [2] 87 59 [2] 85 58 [2] 9e 5e [2] 82 59 [2] 9e 76 }

  condition:
    any of them
}