rule TTP_XOR_MULT_DOSStub_f96f {
  strings:
    $key_f96f = { ad 07 [2] d9 1f [2] 9e 1d [2] d9 0c [2] 97 00 [2] 9b 0a [2] 8c 01 [2] 97 4f [2] aa }

  condition:
    any of them
}