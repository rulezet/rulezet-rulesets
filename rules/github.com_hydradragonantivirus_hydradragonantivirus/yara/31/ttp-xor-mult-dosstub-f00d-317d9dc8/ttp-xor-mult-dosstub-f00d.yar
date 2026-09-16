rule TTP_XOR_MULT_DOSStub_f00d {
  strings:
    $key_f00d = { a4 65 [2] d0 7d [2] 97 7f [2] d0 6e [2] 9e 62 [2] 92 68 [2] 85 63 [2] 9e 2d [2] a3 }

  condition:
    any of them
}