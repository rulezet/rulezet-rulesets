rule TTP_XOR_MULT_DOSStub_8e70 {
  strings:
    $key_8e70 = { da 18 [2] ae 00 [2] e9 02 [2] ae 13 [2] e0 1f [2] ec 15 [2] fb 1e [2] e0 50 [2] dd }

  condition:
    any of them
}