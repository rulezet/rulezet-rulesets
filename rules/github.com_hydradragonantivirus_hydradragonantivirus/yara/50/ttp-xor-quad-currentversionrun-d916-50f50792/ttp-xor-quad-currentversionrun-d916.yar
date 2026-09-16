rule TTP_XOR_QUAD_CurrentVersionRun_d916 {
  strings:
    $key_d916 = { 8a 79 [2] ae 77 [2] 85 5b [2] ab 79 [2] bf 62 [2] b0 78 [2] ae 65 [2] ac 64 [2] b7 62 [2] ab 65 [2] b7 4a }

  condition:
    any of them
}