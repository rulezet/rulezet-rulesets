rule TTP_XOR_MULT_DOSStub_a44c {
  strings:
    $key_a44c = { f0 24 [2] 84 3c [2] c3 3e [2] 84 2f [2] ca 23 [2] c6 29 [2] d1 22 [2] ca 6c [2] f7 }

  condition:
    any of them
}