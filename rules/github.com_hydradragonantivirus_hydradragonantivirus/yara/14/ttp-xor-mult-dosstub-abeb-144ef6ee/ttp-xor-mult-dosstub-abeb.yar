rule TTP_XOR_MULT_DOSStub_abeb {
  strings:
    $key_abeb = { ff 83 [2] 8b 9b [2] cc 99 [2] 8b 88 [2] c5 84 [2] c9 8e [2] de 85 [2] c5 cb [2] f8 }

  condition:
    any of them
}