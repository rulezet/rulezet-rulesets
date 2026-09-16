rule TTP_XOR_QUAD_CurrentVersionRun_d978 {
  strings:
    $key_d978 = { 8a 17 [2] ae 19 [2] 85 35 [2] ab 17 [2] bf 0c [2] b0 16 [2] ae 0b [2] ac 0a [2] b7 0c [2] ab 0b [2] b7 24 }

  condition:
    any of them
}