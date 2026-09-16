rule TTP_XOR_MULT_DOSStub_cae0 {
  strings:
    $key_cae0 = { 9e 88 [2] ea 90 [2] ad 92 [2] ea 83 [2] a4 8f [2] a8 85 [2] bf 8e [2] a4 c0 [2] 99 }

  condition:
    any of them
}