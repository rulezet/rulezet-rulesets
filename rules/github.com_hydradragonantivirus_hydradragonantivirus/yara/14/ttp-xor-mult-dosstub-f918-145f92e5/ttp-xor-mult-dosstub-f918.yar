rule TTP_XOR_MULT_DOSStub_f918 {
  strings:
    $key_f918 = { ad 70 [2] d9 68 [2] 9e 6a [2] d9 7b [2] 97 77 [2] 9b 7d [2] 8c 76 [2] 97 38 [2] aa }

  condition:
    any of them
}