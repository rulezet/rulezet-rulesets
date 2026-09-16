rule TTP_XOR_QUAD_CurrentVersionRun_c236 {
  strings:
    $key_c236 = { 91 59 [2] b5 57 [2] 9e 7b [2] b0 59 [2] a4 42 [2] ab 58 [2] b5 45 [2] b7 44 [2] ac 42 [2] b0 45 [2] ac 6a }

  condition:
    any of them
}