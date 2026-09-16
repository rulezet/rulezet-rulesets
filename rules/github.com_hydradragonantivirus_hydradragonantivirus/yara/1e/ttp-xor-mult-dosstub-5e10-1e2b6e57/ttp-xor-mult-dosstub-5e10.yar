rule TTP_XOR_MULT_DOSStub_5e10 {
  strings:
    $key_5e10 = { 0a 78 [2] 7e 60 [2] 39 62 [2] 7e 73 [2] 30 7f [2] 3c 75 [2] 2b 7e [2] 30 30 [2] 0d }

  condition:
    any of them
}