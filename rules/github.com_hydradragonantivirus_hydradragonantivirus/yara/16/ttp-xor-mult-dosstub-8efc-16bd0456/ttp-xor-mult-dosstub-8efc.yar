rule TTP_XOR_MULT_DOSStub_8efc {
  strings:
    $key_8efc = { da 94 [2] ae 8c [2] e9 8e [2] ae 9f [2] e0 93 [2] ec 99 [2] fb 92 [2] e0 dc [2] dd }

  condition:
    any of them
}