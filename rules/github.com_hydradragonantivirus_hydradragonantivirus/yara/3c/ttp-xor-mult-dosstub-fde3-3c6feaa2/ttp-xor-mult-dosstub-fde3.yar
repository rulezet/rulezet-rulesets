rule TTP_XOR_MULT_DOSStub_fde3 {
  strings:
    $key_fde3 = { a9 8b [2] dd 93 [2] 9a 91 [2] dd 80 [2] 93 8c [2] 9f 86 [2] 88 8d [2] 93 c3 [2] ae }

  condition:
    any of them
}