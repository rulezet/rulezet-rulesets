rule TTP_XOR_QUAD_CurrentVersionRun_d949 {
  strings:
    $key_d949 = { 8a 26 [2] ae 28 [2] 85 04 [2] ab 26 [2] bf 3d [2] b0 27 [2] ae 3a [2] ac 3b [2] b7 3d [2] ab 3a [2] b7 15 }

  condition:
    any of them
}