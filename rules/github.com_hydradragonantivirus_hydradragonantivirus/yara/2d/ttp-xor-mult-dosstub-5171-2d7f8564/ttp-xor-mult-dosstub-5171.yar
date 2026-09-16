rule TTP_XOR_MULT_DOSStub_5171 {
  strings:
    $key_5171 = { 05 19 [2] 71 01 [2] 36 03 [2] 71 12 [2] 3f 1e [2] 33 14 [2] 24 1f [2] 3f 51 [2] 02 }

  condition:
    any of them
}