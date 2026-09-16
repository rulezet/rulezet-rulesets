rule TTP_XOR_MULT_DOSStub_433d {
  strings:
    $key_433d = { 17 55 [2] 63 4d [2] 24 4f [2] 63 5e [2] 2d 52 [2] 21 58 [2] 36 53 [2] 2d 1d [2] 10 }

  condition:
    any of them
}