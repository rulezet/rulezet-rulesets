rule TTP_XOR_MULT_DOSStub_91ba {
  strings:
    $key_91ba = { c5 d2 [2] b1 ca [2] f6 c8 [2] b1 d9 [2] ff d5 [2] f3 df [2] e4 d4 [2] ff 9a [2] c2 }

  condition:
    any of them
}