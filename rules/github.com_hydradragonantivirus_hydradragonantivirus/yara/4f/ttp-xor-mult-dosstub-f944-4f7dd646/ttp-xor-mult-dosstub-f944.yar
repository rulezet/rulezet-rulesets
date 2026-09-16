rule TTP_XOR_MULT_DOSStub_f944 {
  strings:
    $key_f944 = { ad 2c [2] d9 34 [2] 9e 36 [2] d9 27 [2] 97 2b [2] 9b 21 [2] 8c 2a [2] 97 64 [2] aa }

  condition:
    any of them
}