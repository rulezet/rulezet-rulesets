rule TTP_XOR_MULT_DOSStub_760c {
  strings:
    $key_760c = { 22 64 [2] 56 7c [2] 11 7e [2] 56 6f [2] 18 63 [2] 14 69 [2] 03 62 [2] 18 2c [2] 25 }

  condition:
    any of them
}