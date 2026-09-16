rule TTP_XOR_MULT_DOSStub_84c9 {
  strings:
    $key_84c9 = { d0 a1 [2] a4 b9 [2] e3 bb [2] a4 aa [2] ea a6 [2] e6 ac [2] f1 a7 [2] ea e9 [2] d7 }

  condition:
    any of them
}