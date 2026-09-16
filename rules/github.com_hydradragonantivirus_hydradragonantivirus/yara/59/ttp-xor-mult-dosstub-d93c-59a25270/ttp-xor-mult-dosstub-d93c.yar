rule TTP_XOR_MULT_DOSStub_d93c {
  strings:
    $key_d93c = { 8d 54 [2] f9 4c [2] be 4e [2] f9 5f [2] b7 53 [2] bb 59 [2] ac 52 [2] b7 1c [2] 8a }

  condition:
    any of them
}