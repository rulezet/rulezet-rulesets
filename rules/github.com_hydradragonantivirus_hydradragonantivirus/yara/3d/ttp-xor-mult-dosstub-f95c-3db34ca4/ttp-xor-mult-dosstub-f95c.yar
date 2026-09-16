rule TTP_XOR_MULT_DOSStub_f95c {
  strings:
    $key_f95c = { ad 34 [2] d9 2c [2] 9e 2e [2] d9 3f [2] 97 33 [2] 9b 39 [2] 8c 32 [2] 97 7c [2] aa }

  condition:
    any of them
}