rule TTP_XOR_MULT_DOSStub_7a3c {
  strings:
    $key_7a3c = { 2e 54 [2] 5a 4c [2] 1d 4e [2] 5a 5f [2] 14 53 [2] 18 59 [2] 0f 52 [2] 14 1c [2] 29 }

  condition:
    any of them
}