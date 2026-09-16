rule TTP_XOR_MULT_DOSStub_0aca {
  strings:
    $key_0aca = { 5e a2 [2] 2a ba [2] 6d b8 [2] 2a a9 [2] 64 a5 [2] 68 af [2] 7f a4 [2] 64 ea [2] 59 }

  condition:
    any of them
}