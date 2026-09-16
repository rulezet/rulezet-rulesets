rule TTP_XOR_QUAD_CurrentVersionRun_d952 {
  strings:
    $key_d952 = { 8a 3d [2] ae 33 [2] 85 1f [2] ab 3d [2] bf 26 [2] b0 3c [2] ae 21 [2] ac 20 [2] b7 26 [2] ab 21 [2] b7 0e }

  condition:
    any of them
}