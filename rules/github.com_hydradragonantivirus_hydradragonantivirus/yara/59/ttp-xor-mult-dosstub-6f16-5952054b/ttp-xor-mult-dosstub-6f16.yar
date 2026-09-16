rule TTP_XOR_MULT_DOSStub_6f16 {
  strings:
    $key_6f16 = { 3b 7e [2] 4f 66 [2] 08 64 [2] 4f 75 [2] 01 79 [2] 0d 73 [2] 1a 78 [2] 01 36 [2] 3c }

  condition:
    any of them
}