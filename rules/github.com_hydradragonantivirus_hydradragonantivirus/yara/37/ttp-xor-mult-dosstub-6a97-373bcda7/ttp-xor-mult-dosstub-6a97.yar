rule TTP_XOR_MULT_DOSStub_6a97 {
  strings:
    $key_6a97 = { 3e ff [2] 4a e7 [2] 0d e5 [2] 4a f4 [2] 04 f8 [2] 08 f2 [2] 1f f9 [2] 04 b7 [2] 39 }

  condition:
    any of them
}