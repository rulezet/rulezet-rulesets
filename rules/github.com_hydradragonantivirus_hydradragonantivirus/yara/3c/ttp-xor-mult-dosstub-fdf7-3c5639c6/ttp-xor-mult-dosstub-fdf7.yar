rule TTP_XOR_MULT_DOSStub_fdf7 {
  strings:
    $key_fdf7 = { a9 9f [2] dd 87 [2] 9a 85 [2] dd 94 [2] 93 98 [2] 9f 92 [2] 88 99 [2] 93 d7 [2] ae }

  condition:
    any of them
}