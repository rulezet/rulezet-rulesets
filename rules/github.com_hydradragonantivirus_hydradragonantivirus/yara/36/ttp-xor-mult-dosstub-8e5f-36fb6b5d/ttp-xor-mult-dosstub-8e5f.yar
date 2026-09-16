rule TTP_XOR_MULT_DOSStub_8e5f {
  strings:
    $key_8e5f = { da 37 [2] ae 2f [2] e9 2d [2] ae 3c [2] e0 30 [2] ec 3a [2] fb 31 [2] e0 7f [2] dd }

  condition:
    any of them
}