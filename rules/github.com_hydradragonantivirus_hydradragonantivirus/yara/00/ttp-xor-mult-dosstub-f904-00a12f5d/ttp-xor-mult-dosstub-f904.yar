rule TTP_XOR_MULT_DOSStub_f904 {
  strings:
    $key_f904 = { ad 6c [2] d9 74 [2] 9e 76 [2] d9 67 [2] 97 6b [2] 9b 61 [2] 8c 6a [2] 97 24 [2] aa }

  condition:
    any of them
}