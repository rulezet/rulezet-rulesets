rule TTP_XOR_MULT_DOSStub_8a7c {
  strings:
    $key_8a7c = { de 14 [2] aa 0c [2] ed 0e [2] aa 1f [2] e4 13 [2] e8 19 [2] ff 12 [2] e4 5c [2] d9 }

  condition:
    any of them
}