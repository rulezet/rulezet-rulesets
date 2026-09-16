rule TTP_XOR_MULT_DOSStub_8edb {
  strings:
    $key_8edb = { da b3 [2] ae ab [2] e9 a9 [2] ae b8 [2] e0 b4 [2] ec be [2] fb b5 [2] e0 fb [2] dd }

  condition:
    any of them
}