rule TTP_XOR_MULT_DOSStub_abfe {
  strings:
    $key_abfe = { ff 96 [2] 8b 8e [2] cc 8c [2] 8b 9d [2] c5 91 [2] c9 9b [2] de 90 [2] c5 de [2] f8 }

  condition:
    any of them
}