rule TTP_XOR_MULT_DOSStub_ab32 {
  strings:
    $key_ab32 = { ff 5a [2] 8b 42 [2] cc 40 [2] 8b 51 [2] c5 5d [2] c9 57 [2] de 5c [2] c5 12 [2] f8 }

  condition:
    any of them
}