rule TTP_XOR_MULT_DOSStub_8a16 {
  strings:
    $key_8a16 = { de 7e [2] aa 66 [2] ed 64 [2] aa 75 [2] e4 79 [2] e8 73 [2] ff 78 [2] e4 36 [2] d9 }

  condition:
    any of them
}