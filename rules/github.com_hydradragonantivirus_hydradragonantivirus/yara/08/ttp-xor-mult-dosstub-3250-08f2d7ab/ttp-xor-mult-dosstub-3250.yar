rule TTP_XOR_MULT_DOSStub_3250 {
  strings:
    $key_3250 = { 66 38 [2] 12 20 [2] 55 22 [2] 12 33 [2] 5c 3f [2] 50 35 [2] 47 3e [2] 5c 70 [2] 61 }

  condition:
    any of them
}