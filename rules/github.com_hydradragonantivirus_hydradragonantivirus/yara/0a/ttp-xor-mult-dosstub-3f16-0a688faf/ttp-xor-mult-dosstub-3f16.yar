rule TTP_XOR_MULT_DOSStub_3f16 {
  strings:
    $key_3f16 = { 6b 7e [2] 1f 66 [2] 58 64 [2] 1f 75 [2] 51 79 [2] 5d 73 [2] 4a 78 [2] 51 36 [2] 6c }

  condition:
    any of them
}