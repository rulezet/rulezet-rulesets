rule TTP_XOR_QUAD_CurrentVersionRun_d965 {
  strings:
    $key_d965 = { 8a 0a [2] ae 04 [2] 85 28 [2] ab 0a [2] bf 11 [2] b0 0b [2] ae 16 [2] ac 17 [2] b7 11 [2] ab 16 [2] b7 39 }

  condition:
    any of them
}