rule TTP_XOR_MULT_DOSStub_f016 {
  strings:
    $key_f016 = { a4 7e [2] d0 66 [2] 97 64 [2] d0 75 [2] 9e 79 [2] 92 73 [2] 85 78 [2] 9e 36 [2] a3 }

  condition:
    any of them
}