rule TTP_XOR_QUAD_CurrentVersionRun_c266 {
  strings:
    $key_c266 = { 91 09 [2] b5 07 [2] 9e 2b [2] b0 09 [2] a4 12 [2] ab 08 [2] b5 15 [2] b7 14 [2] ac 12 [2] b0 15 [2] ac 3a }

  condition:
    any of them
}