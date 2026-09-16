rule TTP_XOR_MULT_DOSStub_a717 {
  strings:
    $key_a717 = { f3 7f [2] 87 67 [2] c0 65 [2] 87 74 [2] c9 78 [2] c5 72 [2] d2 79 [2] c9 37 [2] f4 }

  condition:
    any of them
}