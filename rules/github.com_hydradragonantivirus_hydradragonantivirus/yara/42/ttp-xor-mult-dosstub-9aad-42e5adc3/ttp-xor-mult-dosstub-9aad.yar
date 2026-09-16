rule TTP_XOR_MULT_DOSStub_9aad {
  strings:
    $key_9aad = { ce c5 [2] ba dd [2] fd df [2] ba ce [2] f4 c2 [2] f8 c8 [2] ef c3 [2] f4 8d [2] c9 }

  condition:
    any of them
}