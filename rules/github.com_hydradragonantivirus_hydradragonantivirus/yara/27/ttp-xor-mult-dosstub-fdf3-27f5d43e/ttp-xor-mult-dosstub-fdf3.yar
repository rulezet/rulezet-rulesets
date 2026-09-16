rule TTP_XOR_MULT_DOSStub_fdf3 {
  strings:
    $key_fdf3 = { a9 9b [2] dd 83 [2] 9a 81 [2] dd 90 [2] 93 9c [2] 9f 96 [2] 88 9d [2] 93 d3 [2] ae }

  condition:
    any of them
}