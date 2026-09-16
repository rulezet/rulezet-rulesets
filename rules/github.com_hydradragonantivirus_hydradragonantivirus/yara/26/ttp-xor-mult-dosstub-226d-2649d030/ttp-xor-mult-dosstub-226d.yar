rule TTP_XOR_MULT_DOSStub_226d {
  strings:
    $key_226d = { 76 05 [2] 02 1d [2] 45 1f [2] 02 0e [2] 4c 02 [2] 40 08 [2] 57 03 [2] 4c 4d [2] 71 }

  condition:
    any of them
}