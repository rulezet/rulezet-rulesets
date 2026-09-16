rule TTP_XOR_MULT_DOSStub_abea {
  strings:
    $key_abea = { ff 82 [2] 8b 9a [2] cc 98 [2] 8b 89 [2] c5 85 [2] c9 8f [2] de 84 [2] c5 ca [2] f8 }

  condition:
    any of them
}