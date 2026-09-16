rule TTP_XOR_QUAD_CurrentVersionRun_d927 {
  strings:
    $key_d927 = { 8a 48 [2] ae 46 [2] 85 6a [2] ab 48 [2] bf 53 [2] b0 49 [2] ae 54 [2] ac 55 [2] b7 53 [2] ab 54 [2] b7 7b }

  condition:
    any of them
}