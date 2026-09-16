rule TTP_XOR_MULT_DOSStub_a402 {
  strings:
    $key_a402 = { f0 6a [2] 84 72 [2] c3 70 [2] 84 61 [2] ca 6d [2] c6 67 [2] d1 6c [2] ca 22 [2] f7 }

  condition:
    any of them
}