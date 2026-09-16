rule TTP_XOR_QUAD_CurrentVersionRun_c254 {
  strings:
    $key_c254 = { 91 3b [2] b5 35 [2] 9e 19 [2] b0 3b [2] a4 20 [2] ab 3a [2] b5 27 [2] b7 26 [2] ac 20 [2] b0 27 [2] ac 08 }

  condition:
    any of them
}