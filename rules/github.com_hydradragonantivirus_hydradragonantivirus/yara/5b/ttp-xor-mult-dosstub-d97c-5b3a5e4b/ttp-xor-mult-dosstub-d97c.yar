rule TTP_XOR_MULT_DOSStub_d97c {
  strings:
    $key_d97c = { 8d 14 [2] f9 0c [2] be 0e [2] f9 1f [2] b7 13 [2] bb 19 [2] ac 12 [2] b7 5c [2] 8a }

  condition:
    any of them
}