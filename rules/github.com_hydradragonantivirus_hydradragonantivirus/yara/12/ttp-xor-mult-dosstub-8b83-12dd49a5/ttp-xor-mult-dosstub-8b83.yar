rule TTP_XOR_MULT_DOSStub_8b83 {
  strings:
    $key_8b83 = { df eb [2] ab f3 [2] ec f1 [2] ab e0 [2] e5 ec [2] e9 e6 [2] fe ed [2] e5 a3 [2] d8 }

  condition:
    any of them
}