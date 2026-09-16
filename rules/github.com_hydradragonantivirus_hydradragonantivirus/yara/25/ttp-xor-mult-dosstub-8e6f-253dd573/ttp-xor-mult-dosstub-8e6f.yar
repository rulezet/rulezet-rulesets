rule TTP_XOR_MULT_DOSStub_8e6f {
  strings:
    $key_8e6f = { da 07 [2] ae 1f [2] e9 1d [2] ae 0c [2] e0 00 [2] ec 0a [2] fb 01 [2] e0 4f [2] dd }

  condition:
    any of them
}