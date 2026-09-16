rule TTP_XOR_MULT_DOSStub_9a8e {
  strings:
    $key_9a8e = { ce e6 [2] ba fe [2] fd fc [2] ba ed [2] f4 e1 [2] f8 eb [2] ef e0 [2] f4 ae [2] c9 }

  condition:
    any of them
}