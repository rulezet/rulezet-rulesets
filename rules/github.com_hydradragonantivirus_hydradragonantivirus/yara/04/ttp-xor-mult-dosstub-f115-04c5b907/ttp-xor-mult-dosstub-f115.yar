rule TTP_XOR_MULT_DOSStub_f115 {
  strings:
    $key_f115 = { a5 7d [2] d1 65 [2] 96 67 [2] d1 76 [2] 9f 7a [2] 93 70 [2] 84 7b [2] 9f 35 [2] a2 }

  condition:
    any of them
}