rule TTP_XOR_QUAD_CurrentVersionRun_d938 {
  strings:
    $key_d938 = { 8a 57 [2] ae 59 [2] 85 75 [2] ab 57 [2] bf 4c [2] b0 56 [2] ae 4b [2] ac 4a [2] b7 4c [2] ab 4b [2] b7 64 }

  condition:
    any of them
}