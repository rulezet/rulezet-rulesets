rule TTP_XOR_MULT_DOSStub_7010 {
  strings:
    $key_7010 = { 24 78 [2] 50 60 [2] 17 62 [2] 50 73 [2] 1e 7f [2] 12 75 [2] 05 7e [2] 1e 30 [2] 23 }

  condition:
    any of them
}