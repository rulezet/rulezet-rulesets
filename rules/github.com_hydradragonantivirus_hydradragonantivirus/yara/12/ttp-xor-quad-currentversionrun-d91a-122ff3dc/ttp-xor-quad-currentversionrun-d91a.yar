rule TTP_XOR_QUAD_CurrentVersionRun_d91a {
  strings:
    $key_d91a = { 8a 75 [2] ae 7b [2] 85 57 [2] ab 75 [2] bf 6e [2] b0 74 [2] ae 69 [2] ac 68 [2] b7 6e [2] ab 69 [2] b7 46 }

  condition:
    any of them
}