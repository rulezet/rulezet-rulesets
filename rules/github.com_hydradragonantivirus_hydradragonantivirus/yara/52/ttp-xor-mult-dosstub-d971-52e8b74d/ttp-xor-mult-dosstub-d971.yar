rule TTP_XOR_MULT_DOSStub_d971 {
  strings:
    $key_d971 = { 8d 19 [2] f9 01 [2] be 03 [2] f9 12 [2] b7 1e [2] bb 14 [2] ac 1f [2] b7 51 [2] 8a }

  condition:
    any of them
}