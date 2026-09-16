rule TTP_XOR_QUAD_CurrentVersionRun_d914 {
  strings:
    $key_d914 = { 8a 7b [2] ae 75 [2] 85 59 [2] ab 7b [2] bf 60 [2] b0 7a [2] ae 67 [2] ac 66 [2] b7 60 [2] ab 67 [2] b7 48 }

  condition:
    any of them
}