rule TTP_XOR_MULT_DOSStub_2151 {
  strings:
    $key_2151 = { 75 39 [2] 01 21 [2] 46 23 [2] 01 32 [2] 4f 3e [2] 43 34 [2] 54 3f [2] 4f 71 [2] 72 }

  condition:
    any of them
}