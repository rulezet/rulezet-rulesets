rule TTP_XOR_QUAD_CurrentVersionRun_f521 {
  strings:
    $key_f521 = { a6 4e [2] 82 40 [2] a9 6c [2] 87 4e [2] 93 55 [2] 9c 4f [2] 82 52 [2] 80 53 [2] 9b 55 [2] 87 52 [2] 9b 7d }

  condition:
    any of them
}