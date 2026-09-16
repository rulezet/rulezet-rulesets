rule TTP_XOR_MULT_DOSStub_f162 {
  strings:
    $key_f162 = { a5 0a [2] d1 12 [2] 96 10 [2] d1 01 [2] 9f 0d [2] 93 07 [2] 84 0c [2] 9f 42 [2] a2 }

  condition:
    any of them
}