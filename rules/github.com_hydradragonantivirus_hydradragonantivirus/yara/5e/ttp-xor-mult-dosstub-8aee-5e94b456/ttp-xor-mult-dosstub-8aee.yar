rule TTP_XOR_MULT_DOSStub_8aee {
  strings:
    $key_8aee = { de 86 [2] aa 9e [2] ed 9c [2] aa 8d [2] e4 81 [2] e8 8b [2] ff 80 [2] e4 ce [2] d9 }

  condition:
    any of them
}