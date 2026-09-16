rule TTP_XOR_MULT_DOSStub_8e8e {
  strings:
    $key_8e8e = { da e6 [2] ae fe [2] e9 fc [2] ae ed [2] e0 e1 [2] ec eb [2] fb e0 [2] e0 ae [2] dd }

  condition:
    any of them
}