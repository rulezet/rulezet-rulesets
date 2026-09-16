rule TTP_XOR_MULT_DOSStub_364c {
  strings:
    $key_364c = { 62 24 [2] 16 3c [2] 51 3e [2] 16 2f [2] 58 23 [2] 54 29 [2] 43 22 [2] 58 6c [2] 65 }

  condition:
    any of them
}