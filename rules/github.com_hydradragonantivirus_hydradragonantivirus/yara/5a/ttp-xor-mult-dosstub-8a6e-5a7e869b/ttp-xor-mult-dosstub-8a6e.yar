rule TTP_XOR_MULT_DOSStub_8a6e {
  strings:
    $key_8a6e = { de 06 [2] aa 1e [2] ed 1c [2] aa 0d [2] e4 01 [2] e8 0b [2] ff 00 [2] e4 4e [2] d9 }

  condition:
    any of them
}