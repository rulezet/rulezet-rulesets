rule TTP_XOR_MULT_DOSStub_9abc {
  strings:
    $key_9abc = { ce d4 [2] ba cc [2] fd ce [2] ba df [2] f4 d3 [2] f8 d9 [2] ef d2 [2] f4 9c [2] c9 }

  condition:
    any of them
}