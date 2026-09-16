rule TTP_XOR_QUAD_CurrentVersionRun_d924 {
  strings:
    $key_d924 = { 8a 4b [2] ae 45 [2] 85 69 [2] ab 4b [2] bf 50 [2] b0 4a [2] ae 57 [2] ac 56 [2] b7 50 [2] ab 57 [2] b7 78 }

  condition:
    any of them
}