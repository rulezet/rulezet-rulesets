rule TTP_XOR_MULT_DOSStub_8e27 {
  strings:
    $key_8e27 = { da 4f [2] ae 57 [2] e9 55 [2] ae 44 [2] e0 48 [2] ec 42 [2] fb 49 [2] e0 07 [2] dd }

  condition:
    any of them
}