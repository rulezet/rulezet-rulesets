rule TTP_XOR_QUAD_CurrentVersionRun_d90a {
  strings:
    $key_d90a = { 8a 65 [2] ae 6b [2] 85 47 [2] ab 65 [2] bf 7e [2] b0 64 [2] ae 79 [2] ac 78 [2] b7 7e [2] ab 79 [2] b7 56 }

  condition:
    any of them
}