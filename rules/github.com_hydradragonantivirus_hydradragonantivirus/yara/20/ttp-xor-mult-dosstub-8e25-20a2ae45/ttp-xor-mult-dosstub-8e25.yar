rule TTP_XOR_MULT_DOSStub_8e25 {
  strings:
    $key_8e25 = { da 4d [2] ae 55 [2] e9 57 [2] ae 46 [2] e0 4a [2] ec 40 [2] fb 4b [2] e0 05 [2] dd }

  condition:
    any of them
}