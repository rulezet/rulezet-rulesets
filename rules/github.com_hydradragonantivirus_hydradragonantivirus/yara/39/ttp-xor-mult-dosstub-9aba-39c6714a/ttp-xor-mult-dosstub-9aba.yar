rule TTP_XOR_MULT_DOSStub_9aba {
  strings:
    $key_9aba = { ce d2 [2] ba ca [2] fd c8 [2] ba d9 [2] f4 d5 [2] f8 df [2] ef d4 [2] f4 9a [2] c9 }

  condition:
    any of them
}