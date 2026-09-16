rule TTP_XOR_MULT_DOSStub_8ef3 {
  strings:
    $key_8ef3 = { da 9b [2] ae 83 [2] e9 81 [2] ae 90 [2] e0 9c [2] ec 96 [2] fb 9d [2] e0 d3 [2] dd }

  condition:
    any of them
}