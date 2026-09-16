rule TTP_XOR_MULT_DOSStub_503d {
  strings:
    $key_503d = { 04 55 [2] 70 4d [2] 37 4f [2] 70 5e [2] 3e 52 [2] 32 58 [2] 25 53 [2] 3e 1d [2] 03 }

  condition:
    any of them
}