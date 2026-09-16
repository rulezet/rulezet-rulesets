rule TTP_XOR_MULT_DOSStub_146d {
  strings:
    $key_146d = { 40 05 [2] 34 1d [2] 73 1f [2] 34 0e [2] 7a 02 [2] 76 08 [2] 61 03 [2] 7a 4d [2] 47 }

  condition:
    any of them
}