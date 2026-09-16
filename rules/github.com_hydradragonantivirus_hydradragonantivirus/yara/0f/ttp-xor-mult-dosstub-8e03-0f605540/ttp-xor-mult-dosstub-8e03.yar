rule TTP_XOR_MULT_DOSStub_8e03 {
  strings:
    $key_8e03 = { da 6b [2] ae 73 [2] e9 71 [2] ae 60 [2] e0 6c [2] ec 66 [2] fb 6d [2] e0 23 [2] dd }

  condition:
    any of them
}