rule TTP_XOR_MULT_DOSStub_8e8d {
  strings:
    $key_8e8d = { da e5 [2] ae fd [2] e9 ff [2] ae ee [2] e0 e2 [2] ec e8 [2] fb e3 [2] e0 ad [2] dd }

  condition:
    any of them
}