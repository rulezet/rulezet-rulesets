rule TTP_XOR_MULT_DOSStub_aede {
  strings:
    $key_aede = { fa b6 [2] 8e ae [2] c9 ac [2] 8e bd [2] c0 b1 [2] cc bb [2] db b0 [2] c0 fe [2] fd }

  condition:
    any of them
}