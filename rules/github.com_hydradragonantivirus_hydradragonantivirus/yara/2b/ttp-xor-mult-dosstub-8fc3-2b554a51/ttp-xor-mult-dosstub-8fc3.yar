rule TTP_XOR_MULT_DOSStub_8fc3 {
  strings:
    $key_8fc3 = { db ab [2] af b3 [2] e8 b1 [2] af a0 [2] e1 ac [2] ed a6 [2] fa ad [2] e1 e3 [2] dc }

  condition:
    any of them
}