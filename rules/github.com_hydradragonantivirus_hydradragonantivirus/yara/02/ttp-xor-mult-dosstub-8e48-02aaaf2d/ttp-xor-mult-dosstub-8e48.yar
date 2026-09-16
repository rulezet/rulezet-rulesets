rule TTP_XOR_MULT_DOSStub_8e48 {
  strings:
    $key_8e48 = { da 20 [2] ae 38 [2] e9 3a [2] ae 2b [2] e0 27 [2] ec 2d [2] fb 26 [2] e0 68 [2] dd }

  condition:
    any of them
}