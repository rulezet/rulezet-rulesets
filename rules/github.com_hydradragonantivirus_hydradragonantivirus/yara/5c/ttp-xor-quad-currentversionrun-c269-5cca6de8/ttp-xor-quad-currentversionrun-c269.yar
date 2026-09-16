rule TTP_XOR_QUAD_CurrentVersionRun_c269 {
  strings:
    $key_c269 = { 91 06 [2] b5 08 [2] 9e 24 [2] b0 06 [2] a4 1d [2] ab 07 [2] b5 1a [2] b7 1b [2] ac 1d [2] b0 1a [2] ac 35 }

  condition:
    any of them
}