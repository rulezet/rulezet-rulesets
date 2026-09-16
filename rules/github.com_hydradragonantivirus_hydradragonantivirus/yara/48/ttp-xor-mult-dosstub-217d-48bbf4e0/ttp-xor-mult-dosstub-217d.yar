rule TTP_XOR_MULT_DOSStub_217d {
  strings:
    $key_217d = { 75 15 [2] 01 0d [2] 46 0f [2] 01 1e [2] 4f 12 [2] 43 18 [2] 54 13 [2] 4f 5d [2] 72 }

  condition:
    any of them
}