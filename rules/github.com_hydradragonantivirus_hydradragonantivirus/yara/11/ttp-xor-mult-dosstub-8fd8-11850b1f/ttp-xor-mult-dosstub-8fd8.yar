rule TTP_XOR_MULT_DOSStub_8fd8 {
  strings:
    $key_8fd8 = { db b0 [2] af a8 [2] e8 aa [2] af bb [2] e1 b7 [2] ed bd [2] fa b6 [2] e1 f8 [2] dc }

  condition:
    any of them
}