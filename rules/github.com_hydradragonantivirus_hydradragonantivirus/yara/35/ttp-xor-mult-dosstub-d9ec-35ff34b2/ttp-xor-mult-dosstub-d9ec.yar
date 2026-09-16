rule TTP_XOR_MULT_DOSStub_d9ec {
  strings:
    $key_d9ec = { 8d 84 [2] f9 9c [2] be 9e [2] f9 8f [2] b7 83 [2] bb 89 [2] ac 82 [2] b7 cc [2] 8a }

  condition:
    any of them
}