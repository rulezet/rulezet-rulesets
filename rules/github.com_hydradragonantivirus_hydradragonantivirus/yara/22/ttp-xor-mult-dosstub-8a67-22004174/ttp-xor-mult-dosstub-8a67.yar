rule TTP_XOR_MULT_DOSStub_8a67 {
  strings:
    $key_8a67 = { de 0f [2] aa 17 [2] ed 15 [2] aa 04 [2] e4 08 [2] e8 02 [2] ff 09 [2] e4 47 [2] d9 }

  condition:
    any of them
}