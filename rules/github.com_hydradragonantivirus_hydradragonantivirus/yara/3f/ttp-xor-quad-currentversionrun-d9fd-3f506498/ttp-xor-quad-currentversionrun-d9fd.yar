rule TTP_XOR_QUAD_CurrentVersionRun_d9fd {
  strings:
    $key_d9fd = { 8a 92 [2] ae 9c [2] 85 b0 [2] ab 92 [2] bf 89 [2] b0 93 [2] ae 8e [2] ac 8f [2] b7 89 [2] ab 8e [2] b7 a1 }

  condition:
    any of them
}