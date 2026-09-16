rule TTP_XOR_MULT_DOSStub_f128 {
  strings:
    $key_f128 = { a5 40 [2] d1 58 [2] 96 5a [2] d1 4b [2] 9f 47 [2] 93 4d [2] 84 46 [2] 9f 08 [2] a2 }

  condition:
    any of them
}