rule TTP_XOR_MULT_DOSStub_8e71 {
  strings:
    $key_8e71 = { da 19 [2] ae 01 [2] e9 03 [2] ae 12 [2] e0 1e [2] ec 14 [2] fb 1f [2] e0 51 [2] dd }

  condition:
    any of them
}