rule TTP_XOR_MULT_DOSStub_cafc {
  strings:
    $key_cafc = { 9e 94 [2] ea 8c [2] ad 8e [2] ea 9f [2] a4 93 [2] a8 99 [2] bf 92 [2] a4 dc [2] 99 }

  condition:
    any of them
}