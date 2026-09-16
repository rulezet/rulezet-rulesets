rule TTP_XOR_MULT_DOSStub_8a1e {
  strings:
    $key_8a1e = { de 76 [2] aa 6e [2] ed 6c [2] aa 7d [2] e4 71 [2] e8 7b [2] ff 70 [2] e4 3e [2] d9 }

  condition:
    any of them
}