rule TTP_XOR_QUAD_CurrentVersionRun_f233 {
  strings:
    $key_f233 = { a1 5c [2] 85 52 [2] ae 7e [2] 80 5c [2] 94 47 [2] 9b 5d [2] 85 40 [2] 87 41 [2] 9c 47 [2] 80 40 [2] 9c 6f }

  condition:
    any of them
}