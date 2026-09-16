rule TTP_XOR_MULT_DOSStub_f51d {
  strings:
    $key_f51d = { a1 75 [2] d5 6d [2] 92 6f [2] d5 7e [2] 9b 72 [2] 97 78 [2] 80 73 [2] 9b 3d [2] a6 }

  condition:
    any of them
}