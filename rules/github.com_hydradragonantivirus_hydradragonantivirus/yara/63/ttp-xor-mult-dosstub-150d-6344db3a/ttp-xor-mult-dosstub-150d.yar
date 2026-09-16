rule TTP_XOR_MULT_DOSStub_150d {
  strings:
    $key_150d = { 41 65 [2] 35 7d [2] 72 7f [2] 35 6e [2] 7b 62 [2] 77 68 [2] 60 63 [2] 7b 2d [2] 46 }

  condition:
    any of them
}