rule TTP_XOR_MULT_DOSStub_06f0 {
  strings:
    $key_06f0 = { 52 98 [2] 26 80 [2] 61 82 [2] 26 93 [2] 68 9f [2] 64 95 [2] 73 9e [2] 68 d0 [2] 55 }

  condition:
    any of them
}