rule TTP_XOR_QUAD_CurrentVersionRun_d928 {
  strings:
    $key_d928 = { 8a 47 [2] ae 49 [2] 85 65 [2] ab 47 [2] bf 5c [2] b0 46 [2] ae 5b [2] ac 5a [2] b7 5c [2] ab 5b [2] b7 74 }

  condition:
    any of them
}