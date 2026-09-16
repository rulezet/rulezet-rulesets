rule TTP_XOR_MULT_DOSStub_f908 {
  strings:
    $key_f908 = { ad 60 [2] d9 78 [2] 9e 7a [2] d9 6b [2] 97 67 [2] 9b 6d [2] 8c 66 [2] 97 28 [2] aa }

  condition:
    any of them
}