rule TTP_XOR_MULT_DOSStub_8e36 {
  strings:
    $key_8e36 = { da 5e [2] ae 46 [2] e9 44 [2] ae 55 [2] e0 59 [2] ec 53 [2] fb 58 [2] e0 16 [2] dd }

  condition:
    any of them
}