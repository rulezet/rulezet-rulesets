rule TTP_XOR_MULT_DOSStub_8e7b {
  strings:
    $key_8e7b = { da 13 [2] ae 0b [2] e9 09 [2] ae 18 [2] e0 14 [2] ec 1e [2] fb 15 [2] e0 5b [2] dd }

  condition:
    any of them
}