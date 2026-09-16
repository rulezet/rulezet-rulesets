rule TTP_XOR_MULT_DOSStub_f428 {
  strings:
    $key_f428 = { a0 40 [2] d4 58 [2] 93 5a [2] d4 4b [2] 9a 47 [2] 96 4d [2] 81 46 [2] 9a 08 [2] a7 }

  condition:
    any of them
}