rule TTP_XOR_MULT_DOSStub_a16e {
  strings:
    $key_a16e = { f5 06 [2] 81 1e [2] c6 1c [2] 81 0d [2] cf 01 [2] c3 0b [2] d4 00 [2] cf 4e [2] f2 }

  condition:
    any of them
}