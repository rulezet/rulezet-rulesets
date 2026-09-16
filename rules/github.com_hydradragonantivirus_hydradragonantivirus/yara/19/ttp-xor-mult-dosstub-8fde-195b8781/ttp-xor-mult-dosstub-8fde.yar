rule TTP_XOR_MULT_DOSStub_8fde {
  strings:
    $key_8fde = { db b6 [2] af ae [2] e8 ac [2] af bd [2] e1 b1 [2] ed bb [2] fa b0 [2] e1 fe [2] dc }

  condition:
    any of them
}