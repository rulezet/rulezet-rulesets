rule TTP_XOR_MULT_DOSStub_8a40 {
  strings:
    $key_8a40 = { de 28 [2] aa 30 [2] ed 32 [2] aa 23 [2] e4 2f [2] e8 25 [2] ff 2e [2] e4 60 [2] d9 }

  condition:
    any of them
}