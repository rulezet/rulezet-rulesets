rule TTP_XOR_MULT_DOSStub_f962 {
  strings:
    $key_f962 = { ad 0a [2] d9 12 [2] 9e 10 [2] d9 01 [2] 97 0d [2] 9b 07 [2] 8c 0c [2] 97 42 [2] aa }

  condition:
    any of them
}