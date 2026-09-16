rule TTP_XOR_MULT_DOSStub_f934 {
  strings:
    $key_f934 = { ad 5c [2] d9 44 [2] 9e 46 [2] d9 57 [2] 97 5b [2] 9b 51 [2] 8c 5a [2] 97 14 [2] aa }

  condition:
    any of them
}