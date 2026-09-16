rule TTP_XOR_MULT_DOSStub_f525 {
  strings:
    $key_f525 = { a1 4d [2] d5 55 [2] 92 57 [2] d5 46 [2] 9b 4a [2] 97 40 [2] 80 4b [2] 9b 05 [2] a6 }

  condition:
    any of them
}