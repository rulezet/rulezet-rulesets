rule TTP_XOR_MULT_DOSStub_d9cb {
  strings:
    $key_d9cb = { 8d a3 [2] f9 bb [2] be b9 [2] f9 a8 [2] b7 a4 [2] bb ae [2] ac a5 [2] b7 eb [2] 8a }

  condition:
    any of them
}