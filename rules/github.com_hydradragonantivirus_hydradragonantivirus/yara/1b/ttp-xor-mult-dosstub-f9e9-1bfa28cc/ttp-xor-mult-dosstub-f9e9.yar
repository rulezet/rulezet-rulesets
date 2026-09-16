rule TTP_XOR_MULT_DOSStub_f9e9 {
  strings:
    $key_f9e9 = { ad 81 [2] d9 99 [2] 9e 9b [2] d9 8a [2] 97 86 [2] 9b 8c [2] 8c 87 [2] 97 c9 [2] aa }

  condition:
    any of them
}