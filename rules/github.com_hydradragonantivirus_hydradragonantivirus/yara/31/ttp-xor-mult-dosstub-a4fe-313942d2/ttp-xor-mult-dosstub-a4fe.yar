rule TTP_XOR_MULT_DOSStub_a4fe {
  strings:
    $key_a4fe = { f0 96 [2] 84 8e [2] c3 8c [2] 84 9d [2] ca 91 [2] c6 9b [2] d1 90 [2] ca de [2] f7 }

  condition:
    any of them
}