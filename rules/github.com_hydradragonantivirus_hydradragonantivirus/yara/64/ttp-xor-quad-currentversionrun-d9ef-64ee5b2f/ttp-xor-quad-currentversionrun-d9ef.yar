rule TTP_XOR_QUAD_CurrentVersionRun_d9ef {
  strings:
    $key_d9ef = { 8a 80 [2] ae 8e [2] 85 a2 [2] ab 80 [2] bf 9b [2] b0 81 [2] ae 9c [2] ac 9d [2] b7 9b [2] ab 9c [2] b7 b3 }

  condition:
    any of them
}