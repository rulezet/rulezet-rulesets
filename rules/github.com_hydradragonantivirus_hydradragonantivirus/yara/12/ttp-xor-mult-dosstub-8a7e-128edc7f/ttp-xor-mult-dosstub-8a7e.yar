rule TTP_XOR_MULT_DOSStub_8a7e {
  strings:
    $key_8a7e = { de 16 [2] aa 0e [2] ed 0c [2] aa 1d [2] e4 11 [2] e8 1b [2] ff 10 [2] e4 5e [2] d9 }

  condition:
    any of them
}