rule TTP_XOR_QUAD_CurrentVersionRun_d976 {
  strings:
    $key_d976 = { 8a 19 [2] ae 17 [2] 85 3b [2] ab 19 [2] bf 02 [2] b0 18 [2] ae 05 [2] ac 04 [2] b7 02 [2] ab 05 [2] b7 2a }

  condition:
    any of them
}