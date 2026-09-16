rule TTP_XOR_MULT_DOSStub_f56d {
  strings:
    $key_f56d = { a1 05 [2] d5 1d [2] 92 1f [2] d5 0e [2] 9b 02 [2] 97 08 [2] 80 03 [2] 9b 4d [2] a6 }

  condition:
    any of them
}