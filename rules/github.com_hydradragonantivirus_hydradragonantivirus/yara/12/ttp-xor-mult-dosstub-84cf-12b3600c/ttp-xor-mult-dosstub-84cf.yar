rule TTP_XOR_MULT_DOSStub_84cf {
  strings:
    $key_84cf = { d0 a7 [2] a4 bf [2] e3 bd [2] a4 ac [2] ea a0 [2] e6 aa [2] f1 a1 [2] ea ef [2] d7 }

  condition:
    any of them
}