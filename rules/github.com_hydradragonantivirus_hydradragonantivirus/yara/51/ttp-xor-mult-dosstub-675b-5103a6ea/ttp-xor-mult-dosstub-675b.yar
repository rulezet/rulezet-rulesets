rule TTP_XOR_MULT_DOSStub_675b {
  strings:
    $key_675b = { 33 33 [2] 47 2b [2] 00 29 [2] 47 38 [2] 09 34 [2] 05 3e [2] 12 35 [2] 09 7b [2] 34 }

  condition:
    any of them
}