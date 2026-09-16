rule TTP_XOR_MULT_DOSStub_0610 {
  strings:
    $key_0610 = { 52 78 [2] 26 60 [2] 61 62 [2] 26 73 [2] 68 7f [2] 64 75 [2] 73 7e [2] 68 30 [2] 55 }

  condition:
    any of them
}