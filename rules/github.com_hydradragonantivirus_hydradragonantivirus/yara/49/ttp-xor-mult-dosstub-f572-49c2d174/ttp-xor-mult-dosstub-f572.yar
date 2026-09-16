rule TTP_XOR_MULT_DOSStub_f572 {
  strings:
    $key_f572 = { a1 1a [2] d5 02 [2] 92 00 [2] d5 11 [2] 9b 1d [2] 97 17 [2] 80 1c [2] 9b 52 [2] a6 }

  condition:
    any of them
}