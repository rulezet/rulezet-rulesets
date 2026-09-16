rule TTP_XOR_MULT_DOSStub_8e16 {
  strings:
    $key_8e16 = { da 7e [2] ae 66 [2] e9 64 [2] ae 75 [2] e0 79 [2] ec 73 [2] fb 78 [2] e0 36 [2] dd }

  condition:
    any of them
}