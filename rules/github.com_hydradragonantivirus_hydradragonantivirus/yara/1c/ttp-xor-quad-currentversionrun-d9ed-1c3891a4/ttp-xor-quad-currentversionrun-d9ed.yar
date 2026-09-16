rule TTP_XOR_QUAD_CurrentVersionRun_d9ed {
  strings:
    $key_d9ed = { 8a 82 [2] ae 8c [2] 85 a0 [2] ab 82 [2] bf 99 [2] b0 83 [2] ae 9e [2] ac 9f [2] b7 99 [2] ab 9e [2] b7 b1 }

  condition:
    any of them
}