rule TTP_XOR_MULT_DOSStub_6a46 {
  strings:
    $key_6a46 = { 3e 2e [2] 4a 36 [2] 0d 34 [2] 4a 25 [2] 04 29 [2] 08 23 [2] 1f 28 [2] 04 66 [2] 39 }

  condition:
    any of them
}