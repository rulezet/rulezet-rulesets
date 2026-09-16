rule TTP_XOR_MULT_DOSStub_f95f {
  strings:
    $key_f95f = { ad 37 [2] d9 2f [2] 9e 2d [2] d9 3c [2] 97 30 [2] 9b 3a [2] 8c 31 [2] 97 7f [2] aa }

  condition:
    any of them
}