rule TTP_XOR_MULT_DOSStub_f06d {
  strings:
    $key_f06d = { a4 05 [2] d0 1d [2] 97 1f [2] d0 0e [2] 9e 02 [2] 92 08 [2] 85 03 [2] 9e 4d [2] a3 }

  condition:
    any of them
}