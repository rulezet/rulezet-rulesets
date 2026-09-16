rule TTP_XOR_MULT_DOSStub_8a5e {
  strings:
    $key_8a5e = { de 36 [2] aa 2e [2] ed 2c [2] aa 3d [2] e4 31 [2] e8 3b [2] ff 30 [2] e4 7e [2] d9 }

  condition:
    any of them
}