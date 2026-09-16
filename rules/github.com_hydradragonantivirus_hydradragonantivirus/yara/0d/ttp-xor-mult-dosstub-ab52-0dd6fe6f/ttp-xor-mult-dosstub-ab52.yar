rule TTP_XOR_MULT_DOSStub_ab52 {
  strings:
    $key_ab52 = { ff 3a [2] 8b 22 [2] cc 20 [2] 8b 31 [2] c5 3d [2] c9 37 [2] de 3c [2] c5 72 [2] f8 }

  condition:
    any of them
}