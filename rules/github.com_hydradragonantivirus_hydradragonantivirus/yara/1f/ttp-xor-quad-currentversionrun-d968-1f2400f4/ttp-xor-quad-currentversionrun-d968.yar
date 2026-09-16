rule TTP_XOR_QUAD_CurrentVersionRun_d968 {
  strings:
    $key_d968 = { 8a 07 [2] ae 09 [2] 85 25 [2] ab 07 [2] bf 1c [2] b0 06 [2] ae 1b [2] ac 1a [2] b7 1c [2] ab 1b [2] b7 34 }

  condition:
    any of them
}