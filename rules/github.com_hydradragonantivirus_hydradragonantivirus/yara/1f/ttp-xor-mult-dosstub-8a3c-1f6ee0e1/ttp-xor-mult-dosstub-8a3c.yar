rule TTP_XOR_MULT_DOSStub_8a3c {
  strings:
    $key_8a3c = { de 54 [2] aa 4c [2] ed 4e [2] aa 5f [2] e4 53 [2] e8 59 [2] ff 52 [2] e4 1c [2] d9 }

  condition:
    any of them
}