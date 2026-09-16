rule TTP_XOR_MULT_DOSStub_8e72 {
  strings:
    $key_8e72 = { da 1a [2] ae 02 [2] e9 00 [2] ae 11 [2] e0 1d [2] ec 17 [2] fb 1c [2] e0 52 [2] dd }

  condition:
    any of them
}