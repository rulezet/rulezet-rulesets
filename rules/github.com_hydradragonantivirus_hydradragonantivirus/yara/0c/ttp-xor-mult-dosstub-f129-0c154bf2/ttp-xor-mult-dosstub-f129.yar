rule TTP_XOR_MULT_DOSStub_f129 {
  strings:
    $key_f129 = { a5 41 [2] d1 59 [2] 96 5b [2] d1 4a [2] 9f 46 [2] 93 4c [2] 84 47 [2] 9f 09 [2] a2 }

  condition:
    any of them
}