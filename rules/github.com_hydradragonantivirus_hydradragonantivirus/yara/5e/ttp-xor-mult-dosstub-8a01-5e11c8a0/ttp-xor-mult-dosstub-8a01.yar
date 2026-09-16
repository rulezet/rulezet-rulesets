rule TTP_XOR_MULT_DOSStub_8a01 {
  strings:
    $key_8a01 = { de 69 [2] aa 71 [2] ed 73 [2] aa 62 [2] e4 6e [2] e8 64 [2] ff 6f [2] e4 21 [2] d9 }

  condition:
    any of them
}