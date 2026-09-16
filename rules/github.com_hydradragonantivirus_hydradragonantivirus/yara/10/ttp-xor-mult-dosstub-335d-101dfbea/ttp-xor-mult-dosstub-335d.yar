rule TTP_XOR_MULT_DOSStub_335d {
  strings:
    $key_335d = { 67 35 [2] 13 2d [2] 54 2f [2] 13 3e [2] 5d 32 [2] 51 38 [2] 46 33 [2] 5d 7d [2] 60 }

  condition:
    any of them
}