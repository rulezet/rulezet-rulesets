rule TTP_XOR_MULT_DOSStub_f534 {
  strings:
    $key_f534 = { a1 5c [2] d5 44 [2] 92 46 [2] d5 57 [2] 9b 5b [2] 97 51 [2] 80 5a [2] 9b 14 [2] a6 }

  condition:
    any of them
}