rule TTP_XOR_MULT_DOSStub_8e22 {
  strings:
    $key_8e22 = { da 4a [2] ae 52 [2] e9 50 [2] ae 41 [2] e0 4d [2] ec 47 [2] fb 4c [2] e0 02 [2] dd }

  condition:
    any of them
}