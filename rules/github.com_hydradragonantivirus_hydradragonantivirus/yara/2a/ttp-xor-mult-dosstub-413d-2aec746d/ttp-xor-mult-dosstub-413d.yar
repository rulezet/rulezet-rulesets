rule TTP_XOR_MULT_DOSStub_413d {
  strings:
    $key_413d = { 15 55 [2] 61 4d [2] 26 4f [2] 61 5e [2] 2f 52 [2] 23 58 [2] 34 53 [2] 2f 1d [2] 12 }

  condition:
    any of them
}