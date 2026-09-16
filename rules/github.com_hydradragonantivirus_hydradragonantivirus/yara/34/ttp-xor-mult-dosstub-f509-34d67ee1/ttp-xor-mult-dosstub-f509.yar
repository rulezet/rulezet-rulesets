rule TTP_XOR_MULT_DOSStub_f509 {
  strings:
    $key_f509 = { a1 61 [2] d5 79 [2] 92 7b [2] d5 6a [2] 9b 66 [2] 97 6c [2] 80 67 [2] 9b 29 [2] a6 }

  condition:
    any of them
}