rule TTP_XOR_MULT_DOSStub_f915 {
  strings:
    $key_f915 = { ad 7d [2] d9 65 [2] 9e 67 [2] d9 76 [2] 97 7a [2] 9b 70 [2] 8c 7b [2] 97 35 [2] aa }

  condition:
    any of them
}