rule TTP_XOR_QUAD_CurrentVersionRun_f526 {
  strings:
    $key_f526 = { a6 49 [2] 82 47 [2] a9 6b [2] 87 49 [2] 93 52 [2] 9c 48 [2] 82 55 [2] 80 54 [2] 9b 52 [2] 87 55 [2] 9b 7a }

  condition:
    any of them
}