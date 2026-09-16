rule TTP_XOR_MULT_DOSStub_8fdb {
  strings:
    $key_8fdb = { db b3 [2] af ab [2] e8 a9 [2] af b8 [2] e1 b4 [2] ed be [2] fa b5 [2] e1 fb [2] dc }

  condition:
    any of them
}