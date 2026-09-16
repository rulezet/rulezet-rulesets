rule TTP_XOR_MULT_DOSStub_8e59 {
  strings:
    $key_8e59 = { da 31 [2] ae 29 [2] e9 2b [2] ae 3a [2] e0 36 [2] ec 3c [2] fb 37 [2] e0 79 [2] dd }

  condition:
    any of them
}