rule TTP_XOR_MULT_DOSStub_fdf1 {
  strings:
    $key_fdf1 = { a9 99 [2] dd 81 [2] 9a 83 [2] dd 92 [2] 93 9e [2] 9f 94 [2] 88 9f [2] 93 d1 [2] ae }

  condition:
    any of them
}