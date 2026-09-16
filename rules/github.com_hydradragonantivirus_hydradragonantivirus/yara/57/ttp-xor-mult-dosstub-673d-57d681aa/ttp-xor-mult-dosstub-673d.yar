rule TTP_XOR_MULT_DOSStub_673d {
  strings:
    $key_673d = { 33 55 [2] 47 4d [2] 00 4f [2] 47 5e [2] 09 52 [2] 05 58 [2] 12 53 [2] 09 1d [2] 34 }

  condition:
    any of them
}