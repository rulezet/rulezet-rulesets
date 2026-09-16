rule TTP_XOR_MULT_DOSStub_061c {
  strings:
    $key_061c = { 52 74 [2] 26 6c [2] 61 6e [2] 26 7f [2] 68 73 [2] 64 79 [2] 73 72 [2] 68 3c [2] 55 }

  condition:
    any of them
}