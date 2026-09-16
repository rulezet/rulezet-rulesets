rule TTP_XOR_QUAD_CurrentVersionRun_d97c {
  strings:
    $key_d97c = { 8a 13 [2] ae 1d [2] 85 31 [2] ab 13 [2] bf 08 [2] b0 12 [2] ae 0f [2] ac 0e [2] b7 08 [2] ab 0f [2] b7 20 }

  condition:
    any of them
}