rule TTP_XOR_MULT_DOSStub_8a0c {
  strings:
    $key_8a0c = { de 64 [2] aa 7c [2] ed 7e [2] aa 6f [2] e4 63 [2] e8 69 [2] ff 62 [2] e4 2c [2] d9 }

  condition:
    any of them
}