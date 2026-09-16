rule TTP_XOR_MULT_DOSStub_8eee {
  strings:
    $key_8eee = { da 86 [2] ae 9e [2] e9 9c [2] ae 8d [2] e0 81 [2] ec 8b [2] fb 80 [2] e0 ce [2] dd }

  condition:
    any of them
}