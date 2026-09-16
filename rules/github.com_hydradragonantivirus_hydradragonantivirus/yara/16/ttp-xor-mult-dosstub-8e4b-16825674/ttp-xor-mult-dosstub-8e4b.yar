rule TTP_XOR_MULT_DOSStub_8e4b {
  strings:
    $key_8e4b = { da 23 [2] ae 3b [2] e9 39 [2] ae 28 [2] e0 24 [2] ec 2e [2] fb 25 [2] e0 6b [2] dd }

  condition:
    any of them
}