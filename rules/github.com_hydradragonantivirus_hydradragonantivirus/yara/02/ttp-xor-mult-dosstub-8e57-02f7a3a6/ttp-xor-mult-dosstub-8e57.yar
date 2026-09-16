rule TTP_XOR_MULT_DOSStub_8e57 {
  strings:
    $key_8e57 = { da 3f [2] ae 27 [2] e9 25 [2] ae 34 [2] e0 38 [2] ec 32 [2] fb 39 [2] e0 77 [2] dd }

  condition:
    any of them
}