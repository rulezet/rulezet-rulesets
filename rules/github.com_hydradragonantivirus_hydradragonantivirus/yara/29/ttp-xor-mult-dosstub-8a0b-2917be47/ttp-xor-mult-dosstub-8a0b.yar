rule TTP_XOR_MULT_DOSStub_8a0b {
  strings:
    $key_8a0b = { de 63 [2] aa 7b [2] ed 79 [2] aa 68 [2] e4 64 [2] e8 6e [2] ff 65 [2] e4 2b [2] d9 }

  condition:
    any of them
}