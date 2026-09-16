rule TTP_XOR_QUAD_CurrentVersionRun_d911 {
  strings:
    $key_d911 = { 8a 7e [2] ae 70 [2] 85 5c [2] ab 7e [2] bf 65 [2] b0 7f [2] ae 62 [2] ac 63 [2] b7 65 [2] ab 62 [2] b7 4d }

  condition:
    any of them
}