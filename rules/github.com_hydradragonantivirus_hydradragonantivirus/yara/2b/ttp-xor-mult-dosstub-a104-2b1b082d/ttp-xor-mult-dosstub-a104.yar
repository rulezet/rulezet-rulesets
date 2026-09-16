rule TTP_XOR_MULT_DOSStub_a104 {
  strings:
    $key_a104 = { f5 6c [2] 81 74 [2] c6 76 [2] 81 67 [2] cf 6b [2] c3 61 [2] d4 6a [2] cf 24 [2] f2 }

  condition:
    any of them
}