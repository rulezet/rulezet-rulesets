rule TTP_XOR_QUAD_CurrentVersionRun_d91c {
  strings:
    $key_d91c = { 8a 73 [2] ae 7d [2] 85 51 [2] ab 73 [2] bf 68 [2] b0 72 [2] ae 6f [2] ac 6e [2] b7 68 [2] ab 6f [2] b7 40 }

  condition:
    any of them
}