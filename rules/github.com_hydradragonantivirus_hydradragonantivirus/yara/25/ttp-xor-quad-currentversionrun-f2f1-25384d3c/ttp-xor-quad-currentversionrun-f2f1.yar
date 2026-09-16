rule TTP_XOR_QUAD_CurrentVersionRun_f2f1 {
  strings:
    $key_f2f1 = { a1 9e [2] 85 90 [2] ae bc [2] 80 9e [2] 94 85 [2] 9b 9f [2] 85 82 [2] 87 83 [2] 9c 85 [2] 80 82 [2] 9c ad }

  condition:
    any of them
}