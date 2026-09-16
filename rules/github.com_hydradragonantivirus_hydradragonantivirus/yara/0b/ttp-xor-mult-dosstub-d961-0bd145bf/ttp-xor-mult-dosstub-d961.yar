rule TTP_XOR_MULT_DOSStub_d961 {
  strings:
    $key_d961 = { 8d 09 [2] f9 11 [2] be 13 [2] f9 02 [2] b7 0e [2] bb 04 [2] ac 0f [2] b7 41 [2] 8a }

  condition:
    any of them
}