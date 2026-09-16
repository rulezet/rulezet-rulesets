rule TTP_XOR_MULT_DOSStub_d457 {
  strings:
    $key_d457 = { 80 3f [2] f4 27 [2] b3 25 [2] f4 34 [2] ba 38 [2] b6 32 [2] a1 39 [2] ba 77 [2] 87 }

  condition:
    any of them
}