rule TTP_XOR_QUAD_CurrentVersionRun_d90b {
  strings:
    $key_d90b = { 8a 64 [2] ae 6a [2] 85 46 [2] ab 64 [2] bf 7f [2] b0 65 [2] ae 78 [2] ac 79 [2] b7 7f [2] ab 78 [2] b7 57 }

  condition:
    any of them
}