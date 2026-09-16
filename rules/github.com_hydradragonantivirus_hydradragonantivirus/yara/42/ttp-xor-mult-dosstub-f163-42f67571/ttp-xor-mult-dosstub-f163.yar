rule TTP_XOR_MULT_DOSStub_f163 {
  strings:
    $key_f163 = { a5 0b [2] d1 13 [2] 96 11 [2] d1 00 [2] 9f 0c [2] 93 06 [2] 84 0d [2] 9f 43 [2] a2 }

  condition:
    any of them
}