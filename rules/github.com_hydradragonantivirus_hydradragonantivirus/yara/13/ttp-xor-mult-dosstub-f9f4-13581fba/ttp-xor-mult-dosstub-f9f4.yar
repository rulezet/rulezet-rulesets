rule TTP_XOR_MULT_DOSStub_f9f4 {
  strings:
    $key_f9f4 = { ad 9c [2] d9 84 [2] 9e 86 [2] d9 97 [2] 97 9b [2] 9b 91 [2] 8c 9a [2] 97 d4 [2] aa }

  condition:
    any of them
}