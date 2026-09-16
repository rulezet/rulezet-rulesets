rule TTP_XOR_QUAD_CurrentVersionRun_f033 {
  strings:
    $key_f033 = { a3 5c [2] 87 52 [2] ac 7e [2] 82 5c [2] 96 47 [2] 99 5d [2] 87 40 [2] 85 41 [2] 9e 47 [2] 82 40 [2] 9e 6f }

  condition:
    any of them
}