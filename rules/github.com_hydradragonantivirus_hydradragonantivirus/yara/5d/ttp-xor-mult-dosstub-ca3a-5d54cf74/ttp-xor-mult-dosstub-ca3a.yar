rule TTP_XOR_MULT_DOSStub_ca3a {
  strings:
    $key_ca3a = { 9e 52 [2] ea 4a [2] ad 48 [2] ea 59 [2] a4 55 [2] a8 5f [2] bf 54 [2] a4 1a [2] 99 }

  condition:
    any of them
}