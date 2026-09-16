rule TTP_XOR_MULT_DOSStub_8e40 {
  strings:
    $key_8e40 = { da 28 [2] ae 30 [2] e9 32 [2] ae 23 [2] e0 2f [2] ec 25 [2] fb 2e [2] e0 60 [2] dd }

  condition:
    any of them
}