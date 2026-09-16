rule TTP_XOR_MULT_DOSStub_8fdc {
  strings:
    $key_8fdc = { db b4 [2] af ac [2] e8 ae [2] af bf [2] e1 b3 [2] ed b9 [2] fa b2 [2] e1 fc [2] dc }

  condition:
    any of them
}