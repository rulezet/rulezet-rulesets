rule TTP_XOR_MULT_DOSStub_285d {
  strings:
    $key_285d = { 7c 35 [2] 08 2d [2] 4f 2f [2] 08 3e [2] 46 32 [2] 4a 38 [2] 5d 33 [2] 46 7d [2] 7b }

  condition:
    any of them
}