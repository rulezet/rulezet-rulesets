rule TTP_XOR_QUAD_CurrentVersionRun_d951 {
  strings:
    $key_d951 = { 8a 3e [2] ae 30 [2] 85 1c [2] ab 3e [2] bf 25 [2] b0 3f [2] ae 22 [2] ac 23 [2] b7 25 [2] ab 22 [2] b7 0d }

  condition:
    any of them
}