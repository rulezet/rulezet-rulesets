rule TTP_XOR_MULT_DOSStub_a721 {
  strings:
    $key_a721 = { f3 49 [2] 87 51 [2] c0 53 [2] 87 42 [2] c9 4e [2] c5 44 [2] d2 4f [2] c9 01 [2] f4 }

  condition:
    any of them
}