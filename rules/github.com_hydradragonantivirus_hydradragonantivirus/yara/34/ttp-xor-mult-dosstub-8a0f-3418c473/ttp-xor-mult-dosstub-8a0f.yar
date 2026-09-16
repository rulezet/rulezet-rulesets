rule TTP_XOR_MULT_DOSStub_8a0f {
  strings:
    $key_8a0f = { de 67 [2] aa 7f [2] ed 7d [2] aa 6c [2] e4 60 [2] e8 6a [2] ff 61 [2] e4 2f [2] d9 }

  condition:
    any of them
}