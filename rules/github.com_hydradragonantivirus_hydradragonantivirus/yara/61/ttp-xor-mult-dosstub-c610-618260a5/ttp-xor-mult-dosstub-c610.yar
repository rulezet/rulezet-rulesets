rule TTP_XOR_MULT_DOSStub_c610 {
  strings:
    $key_c610 = { 92 78 [2] e6 60 [2] a1 62 [2] e6 73 [2] a8 7f [2] a4 75 [2] b3 7e [2] a8 30 [2] 95 }

  condition:
    any of them
}