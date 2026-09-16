rule TTP_XOR_MULT_DOSStub_8e10 {
  strings:
    $key_8e10 = { da 78 [2] ae 60 [2] e9 62 [2] ae 73 [2] e0 7f [2] ec 75 [2] fb 7e [2] e0 30 [2] dd }

  condition:
    any of them
}