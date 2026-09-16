rule TTP_XOR_MULT_DOSStub_8e69 {
  strings:
    $key_8e69 = { da 01 [2] ae 19 [2] e9 1b [2] ae 0a [2] e0 06 [2] ec 0c [2] fb 07 [2] e0 49 [2] dd }

  condition:
    any of them
}