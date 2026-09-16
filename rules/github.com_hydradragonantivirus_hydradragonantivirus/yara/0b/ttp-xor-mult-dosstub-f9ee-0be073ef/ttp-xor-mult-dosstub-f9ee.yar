rule TTP_XOR_MULT_DOSStub_f9ee {
  strings:
    $key_f9ee = { ad 86 [2] d9 9e [2] 9e 9c [2] d9 8d [2] 97 81 [2] 9b 8b [2] 8c 80 [2] 97 ce [2] aa }

  condition:
    any of them
}