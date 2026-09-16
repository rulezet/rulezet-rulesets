rule TTP_XOR_MULT_DOSStub_4741 {
  strings:
    $key_4741 = { 13 29 [2] 67 31 [2] 20 33 [2] 67 22 [2] 29 2e [2] 25 24 [2] 32 2f [2] 29 61 [2] 14 }

  condition:
    any of them
}