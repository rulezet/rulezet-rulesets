rule TTP_XOR_MULT_DOSStub_f563 {
  strings:
    $key_f563 = { a1 0b [2] d5 13 [2] 92 11 [2] d5 00 [2] 9b 0c [2] 97 06 [2] 80 0d [2] 9b 43 [2] a6 }

  condition:
    any of them
}