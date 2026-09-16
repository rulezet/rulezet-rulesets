rule TTP_XOR_MULT_DOSStub_a411 {
  strings:
    $key_a411 = { f0 79 [2] 84 61 [2] c3 63 [2] 84 72 [2] ca 7e [2] c6 74 [2] d1 7f [2] ca 31 [2] f7 }

  condition:
    any of them
}