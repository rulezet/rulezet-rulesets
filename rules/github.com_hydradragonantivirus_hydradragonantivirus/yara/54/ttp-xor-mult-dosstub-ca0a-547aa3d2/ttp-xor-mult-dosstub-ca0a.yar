rule TTP_XOR_MULT_DOSStub_ca0a {
  strings:
    $key_ca0a = { 9e 62 [2] ea 7a [2] ad 78 [2] ea 69 [2] a4 65 [2] a8 6f [2] bf 64 [2] a4 2a [2] 99 }

  condition:
    any of them
}