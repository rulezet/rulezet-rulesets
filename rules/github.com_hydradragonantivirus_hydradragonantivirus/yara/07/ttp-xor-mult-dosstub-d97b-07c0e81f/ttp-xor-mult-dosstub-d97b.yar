rule TTP_XOR_MULT_DOSStub_d97b {
  strings:
    $key_d97b = { 8d 13 [2] f9 0b [2] be 09 [2] f9 18 [2] b7 14 [2] bb 1e [2] ac 15 [2] b7 5b [2] 8a }

  condition:
    any of them
}