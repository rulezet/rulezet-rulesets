rule TTP_XOR_QUAD_CurrentVersionRun_d969 {
  strings:
    $key_d969 = { 8a 06 [2] ae 08 [2] 85 24 [2] ab 06 [2] bf 1d [2] b0 07 [2] ae 1a [2] ac 1b [2] b7 1d [2] ab 1a [2] b7 35 }

  condition:
    any of them
}