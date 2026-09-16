rule TTP_XOR_MULT_DOSStub_8e35 {
  strings:
    $key_8e35 = { da 5d [2] ae 45 [2] e9 47 [2] ae 56 [2] e0 5a [2] ec 50 [2] fb 5b [2] e0 15 [2] dd }

  condition:
    any of them
}