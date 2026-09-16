rule TTP_XOR_QUAD_CurrentVersionRun_d94b {
  strings:
    $key_d94b = { 8a 24 [2] ae 2a [2] 85 06 [2] ab 24 [2] bf 3f [2] b0 25 [2] ae 38 [2] ac 39 [2] b7 3f [2] ab 38 [2] b7 17 }

  condition:
    any of them
}