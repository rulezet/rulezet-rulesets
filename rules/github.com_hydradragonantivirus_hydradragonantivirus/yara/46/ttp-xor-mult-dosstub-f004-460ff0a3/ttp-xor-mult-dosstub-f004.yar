rule TTP_XOR_MULT_DOSStub_f004 {
  strings:
    $key_f004 = { a4 6c [2] d0 74 [2] 97 76 [2] d0 67 [2] 9e 6b [2] 92 61 [2] 85 6a [2] 9e 24 [2] a3 }

  condition:
    any of them
}