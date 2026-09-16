rule TTP_XOR_MULT_DOSStub_f45f {
  strings:
    $key_f45f = { a0 37 [2] d4 2f [2] 93 2d [2] d4 3c [2] 9a 30 [2] 96 3a [2] 81 31 [2] 9a 7f [2] a7 }

  condition:
    any of them
}