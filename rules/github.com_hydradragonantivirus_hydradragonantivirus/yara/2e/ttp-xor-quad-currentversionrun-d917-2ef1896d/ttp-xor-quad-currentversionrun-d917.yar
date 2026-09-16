rule TTP_XOR_QUAD_CurrentVersionRun_d917 {
  strings:
    $key_d917 = { 8a 78 [2] ae 76 [2] 85 5a [2] ab 78 [2] bf 63 [2] b0 79 [2] ae 64 [2] ac 65 [2] b7 63 [2] ab 64 [2] b7 4b }

  condition:
    any of them
}