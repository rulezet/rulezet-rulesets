rule TTP_XOR_MULT_DOSStub_2511 {
  strings:
    $key_2511 = { 71 79 [2] 05 61 [2] 42 63 [2] 05 72 [2] 4b 7e [2] 47 74 [2] 50 7f [2] 4b 31 [2] 76 }

  condition:
    any of them
}