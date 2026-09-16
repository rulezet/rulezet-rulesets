rule TTP_XOR_MULT_DOSStub_8e2a {
  strings:
    $key_8e2a = { da 42 [2] ae 5a [2] e9 58 [2] ae 49 [2] e0 45 [2] ec 4f [2] fb 44 [2] e0 0a [2] dd }

  condition:
    any of them
}