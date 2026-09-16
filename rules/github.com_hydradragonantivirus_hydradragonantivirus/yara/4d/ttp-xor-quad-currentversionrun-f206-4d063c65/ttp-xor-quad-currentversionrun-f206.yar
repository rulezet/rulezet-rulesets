rule TTP_XOR_QUAD_CurrentVersionRun_f206 {
  strings:
    $key_f206 = { a1 69 [2] 85 67 [2] ae 4b [2] 80 69 [2] 94 72 [2] 9b 68 [2] 85 75 [2] 87 74 [2] 9c 72 [2] 80 75 [2] 9c 5a }

  condition:
    any of them
}