rule TTP_XOR_MULT_DOSStub_d95c {
  strings:
    $key_d95c = { 8d 34 [2] f9 2c [2] be 2e [2] f9 3f [2] b7 33 [2] bb 39 [2] ac 32 [2] b7 7c [2] 8a }

  condition:
    any of them
}