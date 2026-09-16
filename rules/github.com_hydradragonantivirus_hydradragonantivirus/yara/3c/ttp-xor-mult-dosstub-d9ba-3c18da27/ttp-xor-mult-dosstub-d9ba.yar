rule TTP_XOR_MULT_DOSStub_d9ba {
  strings:
    $key_d9ba = { 8d d2 [2] f9 ca [2] be c8 [2] f9 d9 [2] b7 d5 [2] bb df [2] ac d4 [2] b7 9a [2] 8a }

  condition:
    any of them
}