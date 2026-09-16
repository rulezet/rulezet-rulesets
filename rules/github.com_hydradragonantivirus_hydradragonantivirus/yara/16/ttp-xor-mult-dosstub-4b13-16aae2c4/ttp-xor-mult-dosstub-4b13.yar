rule TTP_XOR_MULT_DOSStub_4b13 {
  strings:
    $key_4b13 = { 1f 7b [2] 6b 63 [2] 2c 61 [2] 6b 70 [2] 25 7c [2] 29 76 [2] 3e 7d [2] 25 33 [2] 18 }

  condition:
    any of them
}