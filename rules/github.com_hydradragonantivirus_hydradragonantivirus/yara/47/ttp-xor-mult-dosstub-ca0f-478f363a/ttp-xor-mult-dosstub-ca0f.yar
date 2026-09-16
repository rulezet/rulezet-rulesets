rule TTP_XOR_MULT_DOSStub_ca0f {
  strings:
    $key_ca0f = { 9e 67 [2] ea 7f [2] ad 7d [2] ea 6c [2] a4 60 [2] a8 6a [2] bf 61 [2] a4 2f [2] 99 }

  condition:
    any of them
}