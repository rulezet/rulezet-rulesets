rule TTP_XOR_QUAD_CurrentVersionRun_c244 {
  strings:
    $key_c244 = { 91 2b [2] b5 25 [2] 9e 09 [2] b0 2b [2] a4 30 [2] ab 2a [2] b5 37 [2] b7 36 [2] ac 30 [2] b0 37 [2] ac 18 }

  condition:
    any of them
}