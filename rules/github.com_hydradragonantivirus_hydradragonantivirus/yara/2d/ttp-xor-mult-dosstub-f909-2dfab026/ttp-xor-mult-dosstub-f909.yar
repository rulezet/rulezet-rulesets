rule TTP_XOR_MULT_DOSStub_f909 {
  strings:
    $key_f909 = { ad 61 [2] d9 79 [2] 9e 7b [2] d9 6a [2] 97 66 [2] 9b 6c [2] 8c 67 [2] 97 29 [2] aa }

  condition:
    any of them
}