rule TTP_XOR_MULT_DOSStub_fde9 {
  strings:
    $key_fde9 = { a9 81 [2] dd 99 [2] 9a 9b [2] dd 8a [2] 93 86 [2] 9f 8c [2] 88 87 [2] 93 c9 [2] ae }

  condition:
    any of them
}