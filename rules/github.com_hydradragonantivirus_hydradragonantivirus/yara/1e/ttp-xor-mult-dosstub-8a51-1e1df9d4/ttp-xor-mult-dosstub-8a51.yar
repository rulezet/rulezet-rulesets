rule TTP_XOR_MULT_DOSStub_8a51 {
  strings:
    $key_8a51 = { de 39 [2] aa 21 [2] ed 23 [2] aa 32 [2] e4 3e [2] e8 34 [2] ff 3f [2] e4 71 [2] d9 }

  condition:
    any of them
}