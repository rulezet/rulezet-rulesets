rule TTP_XOR_MULT_DOSStub_6201 {
  strings:
    $key_6201 = { 36 69 [2] 42 71 [2] 05 73 [2] 42 62 [2] 0c 6e [2] 00 64 [2] 17 6f [2] 0c 21 [2] 31 }

  condition:
    any of them
}