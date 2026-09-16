rule TTP_XOR_MULT_DOSStub_fde6 {
  strings:
    $key_fde6 = { a9 8e [2] dd 96 [2] 9a 94 [2] dd 85 [2] 93 89 [2] 9f 83 [2] 88 88 [2] 93 c6 [2] ae }

  condition:
    any of them
}