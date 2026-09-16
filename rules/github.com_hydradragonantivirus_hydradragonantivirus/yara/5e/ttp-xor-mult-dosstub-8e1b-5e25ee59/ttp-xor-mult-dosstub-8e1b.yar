rule TTP_XOR_MULT_DOSStub_8e1b {
  strings:
    $key_8e1b = { da 73 [2] ae 6b [2] e9 69 [2] ae 78 [2] e0 74 [2] ec 7e [2] fb 75 [2] e0 3b [2] dd }

  condition:
    any of them
}