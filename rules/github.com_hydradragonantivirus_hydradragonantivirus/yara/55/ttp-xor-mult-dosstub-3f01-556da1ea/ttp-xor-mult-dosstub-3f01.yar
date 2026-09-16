rule TTP_XOR_MULT_DOSStub_3f01 {
  strings:
    $key_3f01 = { 6b 69 [2] 1f 71 [2] 58 73 [2] 1f 62 [2] 51 6e [2] 5d 64 [2] 4a 6f [2] 51 21 [2] 6c }

  condition:
    any of them
}