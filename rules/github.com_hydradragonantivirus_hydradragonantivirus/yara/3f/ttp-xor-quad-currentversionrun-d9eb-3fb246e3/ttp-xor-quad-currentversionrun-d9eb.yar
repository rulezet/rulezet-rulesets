rule TTP_XOR_QUAD_CurrentVersionRun_d9eb {
  strings:
    $key_d9eb = { 8a 84 [2] ae 8a [2] 85 a6 [2] ab 84 [2] bf 9f [2] b0 85 [2] ae 98 [2] ac 99 [2] b7 9f [2] ab 98 [2] b7 b7 }

  condition:
    any of them
}