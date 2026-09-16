rule TTP_XOR_MULT_DOSStub_abef {
  strings:
    $key_abef = { ff 87 [2] 8b 9f [2] cc 9d [2] 8b 8c [2] c5 80 [2] c9 8a [2] de 81 [2] c5 cf [2] f8 }

  condition:
    any of them
}