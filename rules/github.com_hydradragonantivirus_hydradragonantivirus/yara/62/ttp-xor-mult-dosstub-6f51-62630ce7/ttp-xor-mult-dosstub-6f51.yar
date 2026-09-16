rule TTP_XOR_MULT_DOSStub_6f51 {
  strings:
    $key_6f51 = { 3b 39 [2] 4f 21 [2] 08 23 [2] 4f 32 [2] 01 3e [2] 0d 34 [2] 1a 3f [2] 01 71 [2] 3c }

  condition:
    any of them
}