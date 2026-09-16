rule TTP_XOR_MULT_DOSStub_98cf {
  strings:
    $key_98cf = { cc a7 [2] b8 bf [2] ff bd [2] b8 ac [2] f6 a0 [2] fa aa [2] ed a1 [2] f6 ef [2] cb }

  condition:
    any of them
}