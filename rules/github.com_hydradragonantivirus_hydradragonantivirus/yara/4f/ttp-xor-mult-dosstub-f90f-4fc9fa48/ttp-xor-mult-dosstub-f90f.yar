rule TTP_XOR_MULT_DOSStub_f90f {
  strings:
    $key_f90f = { ad 67 [2] d9 7f [2] 9e 7d [2] d9 6c [2] 97 60 [2] 9b 6a [2] 8c 61 [2] 97 2f [2] aa }

  condition:
    any of them
}