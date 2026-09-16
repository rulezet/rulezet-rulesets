rule TTP_XOR_MULT_DOSStub_fdf2 {
  strings:
    $key_fdf2 = { a9 9a [2] dd 82 [2] 9a 80 [2] dd 91 [2] 93 9d [2] 9f 97 [2] 88 9c [2] 93 d2 [2] ae }

  condition:
    any of them
}