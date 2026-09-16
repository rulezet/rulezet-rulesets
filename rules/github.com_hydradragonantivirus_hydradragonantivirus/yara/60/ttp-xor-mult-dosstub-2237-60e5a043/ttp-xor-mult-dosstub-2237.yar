rule TTP_XOR_MULT_DOSStub_2237 {
  strings:
    $key_2237 = { 76 5f [2] 02 47 [2] 45 45 [2] 02 54 [2] 4c 58 [2] 40 52 [2] 57 59 [2] 4c 17 [2] 71 }

  condition:
    any of them
}