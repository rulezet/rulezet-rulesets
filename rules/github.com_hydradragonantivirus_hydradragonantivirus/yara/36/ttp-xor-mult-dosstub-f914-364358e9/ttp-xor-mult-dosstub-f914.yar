rule TTP_XOR_MULT_DOSStub_f914 {
  strings:
    $key_f914 = { ad 7c [2] d9 64 [2] 9e 66 [2] d9 77 [2] 97 7b [2] 9b 71 [2] 8c 7a [2] 97 34 [2] aa }

  condition:
    any of them
}