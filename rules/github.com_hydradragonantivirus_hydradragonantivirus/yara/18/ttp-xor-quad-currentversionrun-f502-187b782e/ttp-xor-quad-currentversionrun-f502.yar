rule TTP_XOR_QUAD_CurrentVersionRun_f502 {
  strings:
    $key_f502 = { a6 6d [2] 82 63 [2] a9 4f [2] 87 6d [2] 93 76 [2] 9c 6c [2] 82 71 [2] 80 70 [2] 9b 76 [2] 87 71 [2] 9b 5e }

  condition:
    any of them
}