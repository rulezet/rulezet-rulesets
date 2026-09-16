rule TTP_XOR_QUAD_CurrentVersionRun_c258 {
  strings:
    $key_c258 = { 91 37 [2] b5 39 [2] 9e 15 [2] b0 37 [2] a4 2c [2] ab 36 [2] b5 2b [2] b7 2a [2] ac 2c [2] b0 2b [2] ac 04 }

  condition:
    any of them
}