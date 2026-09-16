rule TTP_XOR_MULT_DOSStub_8e4e {
  strings:
    $key_8e4e = { da 26 [2] ae 3e [2] e9 3c [2] ae 2d [2] e0 21 [2] ec 2b [2] fb 20 [2] e0 6e [2] dd }

  condition:
    any of them
}