rule TTP_XOR_MULT_DOSStub_8e1f {
  strings:
    $key_8e1f = { da 77 [2] ae 6f [2] e9 6d [2] ae 7c [2] e0 70 [2] ec 7a [2] fb 71 [2] e0 3f [2] dd }

  condition:
    any of them
}