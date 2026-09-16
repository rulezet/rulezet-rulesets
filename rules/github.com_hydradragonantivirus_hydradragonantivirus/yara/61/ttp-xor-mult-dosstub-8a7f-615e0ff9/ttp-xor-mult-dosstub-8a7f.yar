rule TTP_XOR_MULT_DOSStub_8a7f {
  strings:
    $key_8a7f = { de 17 [2] aa 0f [2] ed 0d [2] aa 1c [2] e4 10 [2] e8 1a [2] ff 11 [2] e4 5f [2] d9 }

  condition:
    any of them
}