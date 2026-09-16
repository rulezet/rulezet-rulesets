rule TTP_XOR_MULT_DOSStub_3b13 {
  strings:
    $key_3b13 = { 6f 7b [2] 1b 63 [2] 5c 61 [2] 1b 70 [2] 55 7c [2] 59 76 [2] 4e 7d [2] 55 33 [2] 68 }

  condition:
    any of them
}