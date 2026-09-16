rule TTP_XOR_MULT_DOSStub_abfd {
  strings:
    $key_abfd = { ff 95 [2] 8b 8d [2] cc 8f [2] 8b 9e [2] c5 92 [2] c9 98 [2] de 93 [2] c5 dd [2] f8 }

  condition:
    any of them
}