rule TTP_XOR_MULT_DOSStub_8e11 {
  strings:
    $key_8e11 = { da 79 [2] ae 61 [2] e9 63 [2] ae 72 [2] e0 7e [2] ec 74 [2] fb 7f [2] e0 31 [2] dd }

  condition:
    any of them
}