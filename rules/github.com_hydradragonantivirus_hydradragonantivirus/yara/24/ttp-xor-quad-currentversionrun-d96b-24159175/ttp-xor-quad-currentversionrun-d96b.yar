rule TTP_XOR_QUAD_CurrentVersionRun_d96b {
  strings:
    $key_d96b = { 8a 04 [2] ae 0a [2] 85 26 [2] ab 04 [2] bf 1f [2] b0 05 [2] ae 18 [2] ac 19 [2] b7 1f [2] ab 18 [2] b7 37 }

  condition:
    any of them
}