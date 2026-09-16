rule TTP_XOR_QUAD_CurrentVersionRun_d904 {
  strings:
    $key_d904 = { 8a 6b [2] ae 65 [2] 85 49 [2] ab 6b [2] bf 70 [2] b0 6a [2] ae 77 [2] ac 76 [2] b7 70 [2] ab 77 [2] b7 58 }

  condition:
    any of them
}