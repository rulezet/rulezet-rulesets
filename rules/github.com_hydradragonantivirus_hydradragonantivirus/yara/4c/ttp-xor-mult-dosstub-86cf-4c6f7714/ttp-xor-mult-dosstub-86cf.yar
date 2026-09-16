rule TTP_XOR_MULT_DOSStub_86cf {
  strings:
    $key_86cf = { d2 a7 [2] a6 bf [2] e1 bd [2] a6 ac [2] e8 a0 [2] e4 aa [2] f3 a1 [2] e8 ef [2] d5 }

  condition:
    any of them
}