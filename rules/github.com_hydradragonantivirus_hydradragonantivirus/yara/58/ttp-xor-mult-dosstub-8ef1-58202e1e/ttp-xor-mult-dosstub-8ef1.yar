rule TTP_XOR_MULT_DOSStub_8ef1 {
  strings:
    $key_8ef1 = { da 99 [2] ae 81 [2] e9 83 [2] ae 92 [2] e0 9e [2] ec 94 [2] fb 9f [2] e0 d1 [2] dd }

  condition:
    any of them
}