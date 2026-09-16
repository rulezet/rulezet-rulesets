rule TTP_XOR_QUAD_CurrentVersionRun_d906 {
  strings:
    $key_d906 = { 8a 69 [2] ae 67 [2] 85 4b [2] ab 69 [2] bf 72 [2] b0 68 [2] ae 75 [2] ac 74 [2] b7 72 [2] ab 75 [2] b7 5a }

  condition:
    any of them
}