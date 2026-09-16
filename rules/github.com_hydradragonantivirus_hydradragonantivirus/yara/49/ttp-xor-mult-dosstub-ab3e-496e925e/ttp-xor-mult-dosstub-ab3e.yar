rule TTP_XOR_MULT_DOSStub_ab3e {
  strings:
    $key_ab3e = { ff 56 [2] 8b 4e [2] cc 4c [2] 8b 5d [2] c5 51 [2] c9 5b [2] de 50 [2] c5 1e [2] f8 }

  condition:
    any of them
}