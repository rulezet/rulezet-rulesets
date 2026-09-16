rule TTP_XOR_MULT_DOSStub_8e7a {
  strings:
    $key_8e7a = { da 12 [2] ae 0a [2] e9 08 [2] ae 19 [2] e0 15 [2] ec 1f [2] fb 14 [2] e0 5a [2] dd }

  condition:
    any of them
}