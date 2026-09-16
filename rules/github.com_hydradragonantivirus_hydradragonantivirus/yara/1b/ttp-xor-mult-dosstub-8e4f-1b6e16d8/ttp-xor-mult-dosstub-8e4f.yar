rule TTP_XOR_MULT_DOSStub_8e4f {
  strings:
    $key_8e4f = { da 27 [2] ae 3f [2] e9 3d [2] ae 2c [2] e0 20 [2] ec 2a [2] fb 21 [2] e0 6f [2] dd }

  condition:
    any of them
}