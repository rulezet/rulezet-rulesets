rule TTP_XOR_MULT_DOSStub_8ae6 {
  strings:
    $key_8ae6 = { de 8e [2] aa 96 [2] ed 94 [2] aa 85 [2] e4 89 [2] e8 83 [2] ff 88 [2] e4 c6 [2] d9 }

  condition:
    any of them
}