rule TTP_XOR_QUAD_CurrentVersionRun_c245 {
  strings:
    $key_c245 = { 91 2a [2] b5 24 [2] 9e 08 [2] b0 2a [2] a4 31 [2] ab 2b [2] b5 36 [2] b7 37 [2] ac 31 [2] b0 36 [2] ac 19 }

  condition:
    any of them
}