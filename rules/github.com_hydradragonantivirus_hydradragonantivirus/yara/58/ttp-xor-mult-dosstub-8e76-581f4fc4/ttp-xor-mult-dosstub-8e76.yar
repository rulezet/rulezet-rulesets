rule TTP_XOR_MULT_DOSStub_8e76 {
  strings:
    $key_8e76 = { da 1e [2] ae 06 [2] e9 04 [2] ae 15 [2] e0 19 [2] ec 13 [2] fb 18 [2] e0 56 [2] dd }

  condition:
    any of them
}