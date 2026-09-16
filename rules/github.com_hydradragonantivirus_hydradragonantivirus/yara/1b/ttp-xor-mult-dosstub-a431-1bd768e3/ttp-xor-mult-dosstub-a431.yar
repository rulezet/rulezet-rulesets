rule TTP_XOR_MULT_DOSStub_a431 {
  strings:
    $key_a431 = { f0 59 [2] 84 41 [2] c3 43 [2] 84 52 [2] ca 5e [2] c6 54 [2] d1 5f [2] ca 11 [2] f7 }

  condition:
    any of them
}