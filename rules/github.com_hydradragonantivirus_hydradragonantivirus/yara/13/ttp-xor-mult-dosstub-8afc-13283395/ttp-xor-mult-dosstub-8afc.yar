rule TTP_XOR_MULT_DOSStub_8afc {
  strings:
    $key_8afc = { de 94 [2] aa 8c [2] ed 8e [2] aa 9f [2] e4 93 [2] e8 99 [2] ff 92 [2] e4 dc [2] d9 }

  condition:
    any of them
}