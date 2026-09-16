rule TTP_XOR_MULT_DOSStub_8ef7 {
  strings:
    $key_8ef7 = { da 9f [2] ae 87 [2] e9 85 [2] ae 94 [2] e0 98 [2] ec 92 [2] fb 99 [2] e0 d7 [2] dd }

  condition:
    any of them
}