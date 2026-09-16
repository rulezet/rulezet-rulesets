rule TTP_XOR_MULT_DOSStub_8e00 {
  strings:
    $key_8e00 = { da 68 [2] ae 70 [2] e9 72 [2] ae 63 [2] e0 6f [2] ec 65 [2] fb 6e [2] e0 20 [2] dd }

  condition:
    any of them
}