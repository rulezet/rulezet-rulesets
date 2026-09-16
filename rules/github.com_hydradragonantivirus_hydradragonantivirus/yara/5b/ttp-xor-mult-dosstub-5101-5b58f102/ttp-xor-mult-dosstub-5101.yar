rule TTP_XOR_MULT_DOSStub_5101 {
  strings:
    $key_5101 = { 05 69 [2] 71 71 [2] 36 73 [2] 71 62 [2] 3f 6e [2] 33 64 [2] 24 6f [2] 3f 21 [2] 02 }

  condition:
    any of them
}