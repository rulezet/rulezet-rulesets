rule TTP_XOR_MULT_DOSStub_f53d {
  strings:
    $key_f53d = { a1 55 [2] d5 4d [2] 92 4f [2] d5 5e [2] 9b 52 [2] 97 58 [2] 80 53 [2] 9b 1d [2] a6 }

  condition:
    any of them
}