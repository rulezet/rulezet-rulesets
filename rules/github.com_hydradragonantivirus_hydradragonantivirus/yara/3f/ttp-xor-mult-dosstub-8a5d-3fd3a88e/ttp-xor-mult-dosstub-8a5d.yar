rule TTP_XOR_MULT_DOSStub_8a5d {
  strings:
    $key_8a5d = { de 35 [2] aa 2d [2] ed 2f [2] aa 3e [2] e4 32 [2] e8 38 [2] ff 33 [2] e4 7d [2] d9 }

  condition:
    any of them
}