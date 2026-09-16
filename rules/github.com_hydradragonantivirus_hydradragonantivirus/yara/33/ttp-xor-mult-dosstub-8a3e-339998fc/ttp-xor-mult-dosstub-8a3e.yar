rule TTP_XOR_MULT_DOSStub_8a3e {
  strings:
    $key_8a3e = { de 56 [2] aa 4e [2] ed 4c [2] aa 5d [2] e4 51 [2] e8 5b [2] ff 50 [2] e4 1e [2] d9 }

  condition:
    any of them
}