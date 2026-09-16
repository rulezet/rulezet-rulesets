rule TTP_XOR_MULT_DOSStub_065b {
  strings:
    $key_065b = { 52 33 [2] 26 2b [2] 61 29 [2] 26 38 [2] 68 34 [2] 64 3e [2] 73 35 [2] 68 7b [2] 55 }

  condition:
    any of them
}