rule TTP_XOR_QUAD_CurrentVersionRun_d946 {
  strings:
    $key_d946 = { 8a 29 [2] ae 27 [2] 85 0b [2] ab 29 [2] bf 32 [2] b0 28 [2] ae 35 [2] ac 34 [2] b7 32 [2] ab 35 [2] b7 1a }

  condition:
    any of them
}