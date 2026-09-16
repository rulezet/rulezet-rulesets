rule TTP_XOR_MULT_DOSStub_d93b {
  strings:
    $key_d93b = { 8d 53 [2] f9 4b [2] be 49 [2] f9 58 [2] b7 54 [2] bb 5e [2] ac 55 [2] b7 1b [2] 8a }

  condition:
    any of them
}