rule TTP_XOR_MULT_DOSStub_d921 {
  strings:
    $key_d921 = { 8d 49 [2] f9 51 [2] be 53 [2] f9 42 [2] b7 4e [2] bb 44 [2] ac 4f [2] b7 01 [2] 8a }

  condition:
    any of them
}