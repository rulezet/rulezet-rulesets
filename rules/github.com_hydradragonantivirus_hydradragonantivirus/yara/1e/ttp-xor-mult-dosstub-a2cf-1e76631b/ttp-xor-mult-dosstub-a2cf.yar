rule TTP_XOR_MULT_DOSStub_a2cf {
  strings:
    $key_a2cf = { f6 a7 [2] 82 bf [2] c5 bd [2] 82 ac [2] cc a0 [2] c0 aa [2] d7 a1 [2] cc ef [2] f1 }

  condition:
    any of them
}