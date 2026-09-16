rule TTP_XOR_MULT_DOSStub_8fc5 {
  strings:
    $key_8fc5 = { db ad [2] af b5 [2] e8 b7 [2] af a6 [2] e1 aa [2] ed a0 [2] fa ab [2] e1 e5 [2] dc }

  condition:
    any of them
}