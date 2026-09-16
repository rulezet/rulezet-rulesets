rule TTP_XOR_QUAD_CurrentVersionRun_d97f {
  strings:
    $key_d97f = { 8a 10 [2] ae 1e [2] 85 32 [2] ab 10 [2] bf 0b [2] b0 11 [2] ae 0c [2] ac 0d [2] b7 0b [2] ab 0c [2] b7 23 }

  condition:
    any of them
}