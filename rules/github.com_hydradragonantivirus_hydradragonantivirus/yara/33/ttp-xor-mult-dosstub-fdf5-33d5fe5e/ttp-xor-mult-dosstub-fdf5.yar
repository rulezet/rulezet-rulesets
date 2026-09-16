rule TTP_XOR_MULT_DOSStub_fdf5 {
  strings:
    $key_fdf5 = { a9 9d [2] dd 85 [2] 9a 87 [2] dd 96 [2] 93 9a [2] 9f 90 [2] 88 9b [2] 93 d5 [2] ae }

  condition:
    any of them
}