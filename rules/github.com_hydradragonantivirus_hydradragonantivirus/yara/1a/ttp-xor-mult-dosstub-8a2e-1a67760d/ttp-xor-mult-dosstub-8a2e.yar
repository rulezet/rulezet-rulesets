rule TTP_XOR_MULT_DOSStub_8a2e {
  strings:
    $key_8a2e = { de 46 [2] aa 5e [2] ed 5c [2] aa 4d [2] e4 41 [2] e8 4b [2] ff 40 [2] e4 0e [2] d9 }

  condition:
    any of them
}