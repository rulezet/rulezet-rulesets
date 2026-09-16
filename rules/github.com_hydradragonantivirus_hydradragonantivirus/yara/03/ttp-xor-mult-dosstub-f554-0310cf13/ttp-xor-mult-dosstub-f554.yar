rule TTP_XOR_MULT_DOSStub_f554 {
  strings:
    $key_f554 = { a1 3c [2] d5 24 [2] 92 26 [2] d5 37 [2] 9b 3b [2] 97 31 [2] 80 3a [2] 9b 74 [2] a6 }

  condition:
    any of them
}