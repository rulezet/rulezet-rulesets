rule TTP_XOR_MULT_DOSStub_5051 {
  strings:
    $key_5051 = { 04 39 [2] 70 21 [2] 37 23 [2] 70 32 [2] 3e 3e [2] 32 34 [2] 25 3f [2] 3e 71 [2] 03 }

  condition:
    any of them
}