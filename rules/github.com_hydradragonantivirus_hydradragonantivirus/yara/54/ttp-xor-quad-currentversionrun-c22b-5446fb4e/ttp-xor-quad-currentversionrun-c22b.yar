rule TTP_XOR_QUAD_CurrentVersionRun_c22b {
  strings:
    $key_c22b = { 91 44 [2] b5 4a [2] 9e 66 [2] b0 44 [2] a4 5f [2] ab 45 [2] b5 58 [2] b7 59 [2] ac 5f [2] b0 58 [2] ac 77 }

  condition:
    any of them
}