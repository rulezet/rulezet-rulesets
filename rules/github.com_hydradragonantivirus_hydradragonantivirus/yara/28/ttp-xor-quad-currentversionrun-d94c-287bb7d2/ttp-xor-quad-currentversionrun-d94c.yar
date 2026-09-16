rule TTP_XOR_QUAD_CurrentVersionRun_d94c {
  strings:
    $key_d94c = { 8a 23 [2] ae 2d [2] 85 01 [2] ab 23 [2] bf 38 [2] b0 22 [2] ae 3f [2] ac 3e [2] b7 38 [2] ab 3f [2] b7 10 }

  condition:
    any of them
}