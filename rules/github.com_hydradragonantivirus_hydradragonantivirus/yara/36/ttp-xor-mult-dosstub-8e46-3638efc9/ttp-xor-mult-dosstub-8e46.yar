rule TTP_XOR_MULT_DOSStub_8e46 {
  strings:
    $key_8e46 = { da 2e [2] ae 36 [2] e9 34 [2] ae 25 [2] e0 29 [2] ec 23 [2] fb 28 [2] e0 66 [2] dd }

  condition:
    any of them
}