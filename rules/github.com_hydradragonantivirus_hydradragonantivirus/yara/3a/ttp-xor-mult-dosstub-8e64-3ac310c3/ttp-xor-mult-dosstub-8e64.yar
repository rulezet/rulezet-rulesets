rule TTP_XOR_MULT_DOSStub_8e64 {
  strings:
    $key_8e64 = { da 0c [2] ae 14 [2] e9 16 [2] ae 07 [2] e0 0b [2] ec 01 [2] fb 0a [2] e0 44 [2] dd }

  condition:
    any of them
}