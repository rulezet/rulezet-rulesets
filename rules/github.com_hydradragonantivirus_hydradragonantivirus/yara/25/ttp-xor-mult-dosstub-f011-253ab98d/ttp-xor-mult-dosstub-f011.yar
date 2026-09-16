rule TTP_XOR_MULT_DOSStub_f011 {
  strings:
    $key_f011 = { a4 79 [2] d0 61 [2] 97 63 [2] d0 72 [2] 9e 7e [2] 92 74 [2] 85 7f [2] 9e 31 [2] a3 }

  condition:
    any of them
}