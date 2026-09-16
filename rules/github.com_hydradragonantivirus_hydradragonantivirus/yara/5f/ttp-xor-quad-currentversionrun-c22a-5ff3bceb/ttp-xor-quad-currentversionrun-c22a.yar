rule TTP_XOR_QUAD_CurrentVersionRun_c22a {
  strings:
    $key_c22a = { 91 45 [2] b5 4b [2] 9e 67 [2] b0 45 [2] a4 5e [2] ab 44 [2] b5 59 [2] b7 58 [2] ac 5e [2] b0 59 [2] ac 76 }

  condition:
    any of them
}