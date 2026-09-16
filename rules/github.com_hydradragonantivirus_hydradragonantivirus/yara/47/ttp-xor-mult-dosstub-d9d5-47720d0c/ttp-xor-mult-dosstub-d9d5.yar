rule TTP_XOR_MULT_DOSStub_d9d5 {
  strings:
    $key_d9d5 = { 8d bd [2] f9 a5 [2] be a7 [2] f9 b6 [2] b7 ba [2] bb b0 [2] ac bb [2] b7 f5 [2] 8a }

  condition:
    any of them
}