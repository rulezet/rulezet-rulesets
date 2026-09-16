rule TTP_XOR_QUAD_CurrentVersionRun_d908 {
  strings:
    $key_d908 = { 8a 67 [2] ae 69 [2] 85 45 [2] ab 67 [2] bf 7c [2] b0 66 [2] ae 7b [2] ac 7a [2] b7 7c [2] ab 7b [2] b7 54 }

  condition:
    any of them
}