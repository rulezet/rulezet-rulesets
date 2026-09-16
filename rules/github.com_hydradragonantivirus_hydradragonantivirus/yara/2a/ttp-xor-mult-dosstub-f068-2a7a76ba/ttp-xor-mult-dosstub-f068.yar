rule TTP_XOR_MULT_DOSStub_f068 {
  strings:
    $key_f068 = { a4 00 [2] d0 18 [2] 97 1a [2] d0 0b [2] 9e 07 [2] 92 0d [2] 85 06 [2] 9e 48 [2] a3 }

  condition:
    any of them
}