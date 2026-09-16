rule TTP_XOR_MULT_DOSStub_e73d {
  strings:
    $key_e73d = { b3 55 [2] c7 4d [2] 80 4f [2] c7 5e [2] 89 52 [2] 85 58 [2] 92 53 [2] 89 1d [2] b4 }

  condition:
    any of them
}