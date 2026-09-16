rule TTP_XOR_MULT_DOSStub_f05f {
  strings:
    $key_f05f = { a4 37 [2] d0 2f [2] 97 2d [2] d0 3c [2] 9e 30 [2] 92 3a [2] 85 31 [2] 9e 7f [2] a3 }

  condition:
    any of them
}