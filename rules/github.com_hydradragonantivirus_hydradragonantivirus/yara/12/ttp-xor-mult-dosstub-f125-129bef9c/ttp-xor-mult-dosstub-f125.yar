rule TTP_XOR_MULT_DOSStub_f125 {
  strings:
    $key_f125 = { a5 4d [2] d1 55 [2] 96 57 [2] d1 46 [2] 9f 4a [2] 93 40 [2] 84 4b [2] 9f 05 [2] a2 }

  condition:
    any of them
}