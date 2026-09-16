rule TTP_XOR_MULT_DOSStub_f545 {
  strings:
    $key_f545 = { a1 2d [2] d5 35 [2] 92 37 [2] d5 26 [2] 9b 2a [2] 97 20 [2] 80 2b [2] 9b 65 [2] a6 }

  condition:
    any of them
}