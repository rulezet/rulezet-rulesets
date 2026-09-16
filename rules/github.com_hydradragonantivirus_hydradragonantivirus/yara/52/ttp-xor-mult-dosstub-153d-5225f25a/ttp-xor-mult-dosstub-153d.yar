rule TTP_XOR_MULT_DOSStub_153d {
  strings:
    $key_153d = { 41 55 [2] 35 4d [2] 72 4f [2] 35 5e [2] 7b 52 [2] 77 58 [2] 60 53 [2] 7b 1d [2] 46 }

  condition:
    any of them
}