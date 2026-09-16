rule TTP_XOR_MULT_DOSStub_ddca {
  strings:
    $key_ddca = { 89 a2 [2] fd ba [2] ba b8 [2] fd a9 [2] b3 a5 [2] bf af [2] a8 a4 [2] b3 ea [2] 8e }

  condition:
    any of them
}