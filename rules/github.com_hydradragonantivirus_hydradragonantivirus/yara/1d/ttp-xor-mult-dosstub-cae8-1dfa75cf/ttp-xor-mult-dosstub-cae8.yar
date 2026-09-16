rule TTP_XOR_MULT_DOSStub_cae8 {
  strings:
    $key_cae8 = { 9e 80 [2] ea 98 [2] ad 9a [2] ea 8b [2] a4 87 [2] a8 8d [2] bf 86 [2] a4 c8 [2] 99 }

  condition:
    any of them
}