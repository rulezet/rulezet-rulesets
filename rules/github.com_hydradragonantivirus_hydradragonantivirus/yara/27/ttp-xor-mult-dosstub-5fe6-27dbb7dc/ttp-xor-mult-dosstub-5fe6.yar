rule TTP_XOR_MULT_DOSStub_5fe6 {
  strings:
    $key_5fe6 = { 0b 8e [2] 7f 96 [2] 38 94 [2] 7f 85 [2] 31 89 [2] 3d 83 [2] 2a 88 [2] 31 c6 [2] 0c }

  condition:
    any of them
}