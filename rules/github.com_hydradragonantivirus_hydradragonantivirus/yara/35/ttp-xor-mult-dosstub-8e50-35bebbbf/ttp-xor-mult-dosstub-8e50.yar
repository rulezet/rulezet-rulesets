rule TTP_XOR_MULT_DOSStub_8e50 {
  strings:
    $key_8e50 = { da 38 [2] ae 20 [2] e9 22 [2] ae 33 [2] e0 3f [2] ec 35 [2] fb 3e [2] e0 70 [2] dd }

  condition:
    any of them
}