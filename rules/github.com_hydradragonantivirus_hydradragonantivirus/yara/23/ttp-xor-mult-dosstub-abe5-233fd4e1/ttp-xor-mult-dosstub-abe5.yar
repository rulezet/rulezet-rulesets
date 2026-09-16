rule TTP_XOR_MULT_DOSStub_abe5 {
  strings:
    $key_abe5 = { ff 8d [2] 8b 95 [2] cc 97 [2] 8b 86 [2] c5 8a [2] c9 80 [2] de 8b [2] c5 c5 [2] f8 }

  condition:
    any of them
}