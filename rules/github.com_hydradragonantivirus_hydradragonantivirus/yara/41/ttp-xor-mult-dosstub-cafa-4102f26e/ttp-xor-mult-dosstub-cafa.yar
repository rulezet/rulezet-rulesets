rule TTP_XOR_MULT_DOSStub_cafa {
  strings:
    $key_cafa = { 9e 92 [2] ea 8a [2] ad 88 [2] ea 99 [2] a4 95 [2] a8 9f [2] bf 94 [2] a4 da [2] 99 }

  condition:
    any of them
}