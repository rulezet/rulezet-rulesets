rule TTP_XOR_MULT_DOSStub_a109 {
  strings:
    $key_a109 = { f5 61 [2] 81 79 [2] c6 7b [2] 81 6a [2] cf 66 [2] c3 6c [2] d4 67 [2] cf 29 [2] f2 }

  condition:
    any of them
}