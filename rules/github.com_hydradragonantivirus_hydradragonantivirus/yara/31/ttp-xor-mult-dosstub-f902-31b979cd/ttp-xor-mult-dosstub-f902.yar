rule TTP_XOR_MULT_DOSStub_f902 {
  strings:
    $key_f902 = { ad 6a [2] d9 72 [2] 9e 70 [2] d9 61 [2] 97 6d [2] 9b 67 [2] 8c 6c [2] 97 22 [2] aa }

  condition:
    any of them
}