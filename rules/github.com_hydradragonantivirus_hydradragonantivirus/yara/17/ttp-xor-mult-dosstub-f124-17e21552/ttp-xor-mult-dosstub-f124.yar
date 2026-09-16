rule TTP_XOR_MULT_DOSStub_f124 {
  strings:
    $key_f124 = { a5 4c [2] d1 54 [2] 96 56 [2] d1 47 [2] 9f 4b [2] 93 41 [2] 84 4a [2] 9f 04 [2] a2 }

  condition:
    any of them
}