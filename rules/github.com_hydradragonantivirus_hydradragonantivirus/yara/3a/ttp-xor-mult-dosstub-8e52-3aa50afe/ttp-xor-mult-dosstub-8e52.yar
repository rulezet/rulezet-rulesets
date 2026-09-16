rule TTP_XOR_MULT_DOSStub_8e52 {
  strings:
    $key_8e52 = { da 3a [2] ae 22 [2] e9 20 [2] ae 31 [2] e0 3d [2] ec 37 [2] fb 3c [2] e0 72 [2] dd }

  condition:
    any of them
}