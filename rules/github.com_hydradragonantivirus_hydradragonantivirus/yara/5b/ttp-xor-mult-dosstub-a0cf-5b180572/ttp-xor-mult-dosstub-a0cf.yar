rule TTP_XOR_MULT_DOSStub_a0cf {
  strings:
    $key_a0cf = { f4 a7 [2] 80 bf [2] c7 bd [2] 80 ac [2] ce a0 [2] c2 aa [2] d5 a1 [2] ce ef [2] f3 }

  condition:
    any of them
}