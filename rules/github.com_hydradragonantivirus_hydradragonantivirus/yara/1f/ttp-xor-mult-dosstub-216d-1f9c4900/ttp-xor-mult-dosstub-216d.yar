rule TTP_XOR_MULT_DOSStub_216d {
  strings:
    $key_216d = { 75 05 [2] 01 1d [2] 46 1f [2] 01 0e [2] 4f 02 [2] 43 08 [2] 54 03 [2] 4f 4d [2] 72 }

  condition:
    any of them
}