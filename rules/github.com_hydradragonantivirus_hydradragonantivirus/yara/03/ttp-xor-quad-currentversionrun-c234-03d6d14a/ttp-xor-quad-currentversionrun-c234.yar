rule TTP_XOR_QUAD_CurrentVersionRun_c234 {
  strings:
    $key_c234 = { 91 5b [2] b5 55 [2] 9e 79 [2] b0 5b [2] a4 40 [2] ab 5a [2] b5 47 [2] b7 46 [2] ac 40 [2] b0 47 [2] ac 68 }

  condition:
    any of them
}