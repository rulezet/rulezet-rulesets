rule TTP_XOR_MULT_DOSStub_8ee7 {
  strings:
    $key_8ee7 = { da 8f [2] ae 97 [2] e9 95 [2] ae 84 [2] e0 88 [2] ec 82 [2] fb 89 [2] e0 c7 [2] dd }

  condition:
    any of them
}