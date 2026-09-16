rule TTP_XOR_MULT_DOSStub_9ab8 {
  strings:
    $key_9ab8 = { ce d0 [2] ba c8 [2] fd ca [2] ba db [2] f4 d7 [2] f8 dd [2] ef d6 [2] f4 98 [2] c9 }

  condition:
    any of them
}