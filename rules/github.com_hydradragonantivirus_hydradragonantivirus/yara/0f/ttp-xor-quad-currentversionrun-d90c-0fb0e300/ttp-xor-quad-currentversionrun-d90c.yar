rule TTP_XOR_QUAD_CurrentVersionRun_d90c {
  strings:
    $key_d90c = { 8a 63 [2] ae 6d [2] 85 41 [2] ab 63 [2] bf 78 [2] b0 62 [2] ae 7f [2] ac 7e [2] b7 78 [2] ab 7f [2] b7 50 }

  condition:
    any of them
}