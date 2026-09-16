rule TTP_XOR_MULT_DOSStub_8e14 {
  strings:
    $key_8e14 = { da 7c [2] ae 64 [2] e9 66 [2] ae 77 [2] e0 7b [2] ec 71 [2] fb 7a [2] e0 34 [2] dd }

  condition:
    any of them
}