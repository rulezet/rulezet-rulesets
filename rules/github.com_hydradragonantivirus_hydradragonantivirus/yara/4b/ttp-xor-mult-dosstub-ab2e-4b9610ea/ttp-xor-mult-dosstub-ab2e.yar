rule TTP_XOR_MULT_DOSStub_ab2e {
  strings:
    $key_ab2e = { ff 46 [2] 8b 5e [2] cc 5c [2] 8b 4d [2] c5 41 [2] c9 4b [2] de 40 [2] c5 0e [2] f8 }

  condition:
    any of them
}