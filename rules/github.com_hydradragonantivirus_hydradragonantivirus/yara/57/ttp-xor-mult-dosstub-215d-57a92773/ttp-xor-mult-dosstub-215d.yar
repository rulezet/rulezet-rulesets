rule TTP_XOR_MULT_DOSStub_215d {
  strings:
    $key_215d = { 75 35 [2] 01 2d [2] 46 2f [2] 01 3e [2] 4f 32 [2] 43 38 [2] 54 33 [2] 4f 7d [2] 72 }

  condition:
    any of them
}