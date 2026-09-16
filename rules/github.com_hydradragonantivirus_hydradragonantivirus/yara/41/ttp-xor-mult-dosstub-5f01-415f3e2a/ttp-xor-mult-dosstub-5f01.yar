rule TTP_XOR_MULT_DOSStub_5f01 {
  strings:
    $key_5f01 = { 0b 69 [2] 7f 71 [2] 38 73 [2] 7f 62 [2] 31 6e [2] 3d 64 [2] 2a 6f [2] 31 21 [2] 0c }

  condition:
    any of them
}