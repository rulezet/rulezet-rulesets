rule TTP_XOR_MULT_DOSStub_8e34 {
  strings:
    $key_8e34 = { da 5c [2] ae 44 [2] e9 46 [2] ae 57 [2] e0 5b [2] ec 51 [2] fb 5a [2] e0 14 [2] dd }

  condition:
    any of them
}