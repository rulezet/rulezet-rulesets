rule TTP_XOR_MULT_DOSStub_8ae0 {
  strings:
    $key_8ae0 = { de 88 [2] aa 90 [2] ed 92 [2] aa 83 [2] e4 8f [2] e8 85 [2] ff 8e [2] e4 c0 [2] d9 }

  condition:
    any of them
}