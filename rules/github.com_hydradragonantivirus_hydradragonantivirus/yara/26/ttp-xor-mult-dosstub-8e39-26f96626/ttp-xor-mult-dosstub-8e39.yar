rule TTP_XOR_MULT_DOSStub_8e39 {
  strings:
    $key_8e39 = { da 51 [2] ae 49 [2] e9 4b [2] ae 5a [2] e0 56 [2] ec 5c [2] fb 57 [2] e0 19 [2] dd }

  condition:
    any of them
}