rule TTP_XOR_MULT_DOSStub_8afa {
  strings:
    $key_8afa = { de 92 [2] aa 8a [2] ed 88 [2] aa 99 [2] e4 95 [2] e8 9f [2] ff 94 [2] e4 da [2] d9 }

  condition:
    any of them
}