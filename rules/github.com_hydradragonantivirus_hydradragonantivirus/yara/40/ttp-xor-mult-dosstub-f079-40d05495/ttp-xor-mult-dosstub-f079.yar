rule TTP_XOR_MULT_DOSStub_f079 {
  strings:
    $key_f079 = { a4 11 [2] d0 09 [2] 97 0b [2] d0 1a [2] 9e 16 [2] 92 1c [2] 85 17 [2] 9e 59 [2] a3 }

  condition:
    any of them
}