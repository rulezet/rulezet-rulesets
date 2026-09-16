rule TTP_XOR_MULT_DOSStub_93c2 {
  strings:
    $key_93c2 = { c7 aa [2] b3 b2 [2] f4 b0 [2] b3 a1 [2] fd ad [2] f1 a7 [2] e6 ac [2] fd e2 [2] c0 }

  condition:
    any of them
}