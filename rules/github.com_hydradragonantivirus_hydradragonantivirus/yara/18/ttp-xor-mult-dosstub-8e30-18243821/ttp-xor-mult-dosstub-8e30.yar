rule TTP_XOR_MULT_DOSStub_8e30 {
  strings:
    $key_8e30 = { da 58 [2] ae 40 [2] e9 42 [2] ae 53 [2] e0 5f [2] ec 55 [2] fb 5e [2] e0 10 [2] dd }

  condition:
    any of them
}