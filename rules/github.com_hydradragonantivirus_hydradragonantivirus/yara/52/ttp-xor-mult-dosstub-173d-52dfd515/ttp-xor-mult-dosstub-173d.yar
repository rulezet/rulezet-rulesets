rule TTP_XOR_MULT_DOSStub_173d {
  strings:
    $key_173d = { 43 55 [2] 37 4d [2] 70 4f [2] 37 5e [2] 79 52 [2] 75 58 [2] 62 53 [2] 79 1d [2] 44 }

  condition:
    any of them
}