rule TTP_XOR_QUAD_CurrentVersionRun_d929 {
  strings:
    $key_d929 = { 8a 46 [2] ae 48 [2] 85 64 [2] ab 46 [2] bf 5d [2] b0 47 [2] ae 5a [2] ac 5b [2] b7 5d [2] ab 5a [2] b7 75 }

  condition:
    any of them
}