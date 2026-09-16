rule TTP_XOR_MULT_DOSStub_8afe {
  strings:
    $key_8afe = { de 96 [2] aa 8e [2] ed 8c [2] aa 9d [2] e4 91 [2] e8 9b [2] ff 90 [2] e4 de [2] d9 }

  condition:
    any of them
}