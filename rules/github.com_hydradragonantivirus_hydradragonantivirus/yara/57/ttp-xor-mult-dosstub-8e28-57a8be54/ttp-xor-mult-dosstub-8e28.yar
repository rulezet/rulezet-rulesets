rule TTP_XOR_MULT_DOSStub_8e28 {
  strings:
    $key_8e28 = { da 40 [2] ae 58 [2] e9 5a [2] ae 4b [2] e0 47 [2] ec 4d [2] fb 46 [2] e0 08 [2] dd }

  condition:
    any of them
}