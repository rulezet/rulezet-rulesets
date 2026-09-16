rule TTP_XOR_MULT_DOSStub_8a77 {
  strings:
    $key_8a77 = { de 1f [2] aa 07 [2] ed 05 [2] aa 14 [2] e4 18 [2] e8 12 [2] ff 19 [2] e4 57 [2] d9 }

  condition:
    any of them
}