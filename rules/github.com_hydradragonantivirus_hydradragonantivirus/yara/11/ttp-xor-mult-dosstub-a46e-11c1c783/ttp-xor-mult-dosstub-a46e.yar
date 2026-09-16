rule TTP_XOR_MULT_DOSStub_a46e {
  strings:
    $key_a46e = { f0 06 [2] 84 1e [2] c3 1c [2] 84 0d [2] ca 01 [2] c6 0b [2] d1 00 [2] ca 4e [2] f7 }

  condition:
    any of them
}