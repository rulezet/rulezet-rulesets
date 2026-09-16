rule TTP_XOR_MULT_DOSStub_8e2d {
  strings:
    $key_8e2d = { da 45 [2] ae 5d [2] e9 5f [2] ae 4e [2] e0 42 [2] ec 48 [2] fb 43 [2] e0 0d [2] dd }

  condition:
    any of them
}