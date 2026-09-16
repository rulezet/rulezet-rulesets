rule TTP_XOR_MULT_DOSStub_fdf6 {
  strings:
    $key_fdf6 = { a9 9e [2] dd 86 [2] 9a 84 [2] dd 95 [2] 93 99 [2] 9f 93 [2] 88 98 [2] 93 d6 [2] ae }

  condition:
    any of them
}