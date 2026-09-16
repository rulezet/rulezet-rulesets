rule TTP_XOR_QUAD_CurrentVersionRun_f522 {
  strings:
    $key_f522 = { a6 4d [2] 82 43 [2] a9 6f [2] 87 4d [2] 93 56 [2] 9c 4c [2] 82 51 [2] 80 50 [2] 9b 56 [2] 87 51 [2] 9b 7e }

  condition:
    any of them
}