rule TTP_XOR_QUAD_CurrentVersionRun_d58a {
  strings:
    $key_d58a = { 86 e5 [2] a2 eb [2] 89 c7 [2] a7 e5 [2] b3 fe [2] bc e4 [2] a2 f9 [2] a0 f8 [2] bb fe [2] a7 f9 [2] bb d6 }

  condition:
    any of them
}