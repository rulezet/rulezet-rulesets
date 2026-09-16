rule TTP_XOR_MULT_DOSStub_8a66 {
  strings:
    $key_8a66 = { de 0e [2] aa 16 [2] ed 14 [2] aa 05 [2] e4 09 [2] e8 03 [2] ff 08 [2] e4 46 [2] d9 }

  condition:
    any of them
}