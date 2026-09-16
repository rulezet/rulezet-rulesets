rule TTP_XOR_MULT_DOSStub_fdf8 {
  strings:
    $key_fdf8 = { a9 90 [2] dd 88 [2] 9a 8a [2] dd 9b [2] 93 97 [2] 9f 9d [2] 88 96 [2] 93 d8 [2] ae }

  condition:
    any of them
}