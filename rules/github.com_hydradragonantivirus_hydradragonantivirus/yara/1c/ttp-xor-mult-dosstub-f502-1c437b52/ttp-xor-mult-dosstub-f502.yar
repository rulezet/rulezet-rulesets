rule TTP_XOR_MULT_DOSStub_f502 {
  strings:
    $key_f502 = { a1 6a [2] d5 72 [2] 92 70 [2] d5 61 [2] 9b 6d [2] 97 67 [2] 80 6c [2] 9b 22 [2] a6 }

  condition:
    any of them
}