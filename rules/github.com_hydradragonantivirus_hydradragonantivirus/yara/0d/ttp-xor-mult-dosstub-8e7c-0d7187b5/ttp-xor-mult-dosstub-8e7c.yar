rule TTP_XOR_MULT_DOSStub_8e7c {
  strings:
    $key_8e7c = { da 14 [2] ae 0c [2] e9 0e [2] ae 1f [2] e0 13 [2] ec 19 [2] fb 12 [2] e0 5c [2] dd }

  condition:
    any of them
}