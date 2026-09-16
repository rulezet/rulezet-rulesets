rule TTP_XOR_MULT_DOSStub_eaca {
  strings:
    $key_eaca = { be a2 [2] ca ba [2] 8d b8 [2] ca a9 [2] 84 a5 [2] 88 af [2] 9f a4 [2] 84 ea [2] b9 }

  condition:
    any of them
}