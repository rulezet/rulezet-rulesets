rule TTP_XOR_QUAD_CurrentVersionRun_d95d {
  strings:
    $key_d95d = { 8a 32 [2] ae 3c [2] 85 10 [2] ab 32 [2] bf 29 [2] b0 33 [2] ae 2e [2] ac 2f [2] b7 29 [2] ab 2e [2] b7 01 }

  condition:
    any of them
}