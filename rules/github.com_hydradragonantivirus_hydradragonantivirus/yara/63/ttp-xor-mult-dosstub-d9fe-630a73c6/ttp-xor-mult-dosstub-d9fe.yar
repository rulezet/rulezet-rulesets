rule TTP_XOR_MULT_DOSStub_d9fe {
  strings:
    $key_d9fe = { 8d 96 [2] f9 8e [2] be 8c [2] f9 9d [2] b7 91 [2] bb 9b [2] ac 90 [2] b7 de [2] 8a }

  condition:
    any of them
}