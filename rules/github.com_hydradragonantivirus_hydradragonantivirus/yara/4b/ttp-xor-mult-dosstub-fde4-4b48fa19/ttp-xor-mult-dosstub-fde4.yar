rule TTP_XOR_MULT_DOSStub_fde4 {
  strings:
    $key_fde4 = { a9 8c [2] dd 94 [2] 9a 96 [2] dd 87 [2] 93 8b [2] 9f 81 [2] 88 8a [2] 93 c4 [2] ae }

  condition:
    any of them
}