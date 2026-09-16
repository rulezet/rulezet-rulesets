rule TTP_XOR_MULT_DOSStub_d0ee {
  strings:
    $key_d0ee = { 84 86 [2] f0 9e [2] b7 9c [2] f0 8d [2] be 81 [2] b2 8b [2] a5 80 [2] be ce [2] 83 }

  condition:
    any of them
}