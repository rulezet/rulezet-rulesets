rule TTP_XOR_MULT_DOSStub_2f16 {
  strings:
    $key_2f16 = { 7b 7e [2] 0f 66 [2] 48 64 [2] 0f 75 [2] 41 79 [2] 4d 73 [2] 5a 78 [2] 41 36 [2] 7c }

  condition:
    any of them
}