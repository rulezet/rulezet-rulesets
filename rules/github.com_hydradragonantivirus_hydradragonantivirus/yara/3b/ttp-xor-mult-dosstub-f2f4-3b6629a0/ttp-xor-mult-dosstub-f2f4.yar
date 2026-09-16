rule TTP_XOR_MULT_DOSStub_f2f4 {
  strings:
    $key_f2f4 = { a6 9c [2] d2 84 [2] 95 86 [2] d2 97 [2] 9c 9b [2] 90 91 [2] 87 9a [2] 9c d4 [2] a1 }

  condition:
    any of them
}