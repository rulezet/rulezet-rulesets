rule TTP_XOR_MULT_DOSStub_7a10 {
  strings:
    $key_7a10 = { 2e 78 [2] 5a 60 [2] 1d 62 [2] 5a 73 [2] 14 7f [2] 18 75 [2] 0f 7e [2] 14 30 [2] 29 }

  condition:
    any of them
}