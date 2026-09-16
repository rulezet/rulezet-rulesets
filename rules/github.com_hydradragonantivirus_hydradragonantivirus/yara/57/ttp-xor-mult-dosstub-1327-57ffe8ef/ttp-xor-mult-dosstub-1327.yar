rule TTP_XOR_MULT_DOSStub_1327 {
  strings:
    $key_1327 = { 47 4f [2] 33 57 [2] 74 55 [2] 33 44 [2] 7d 48 [2] 71 42 [2] 66 49 [2] 7d 07 [2] 40 }

  condition:
    any of them
}