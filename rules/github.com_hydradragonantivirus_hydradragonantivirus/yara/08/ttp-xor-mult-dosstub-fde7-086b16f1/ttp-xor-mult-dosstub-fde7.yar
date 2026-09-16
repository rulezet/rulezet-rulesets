rule TTP_XOR_MULT_DOSStub_fde7 {
  strings:
    $key_fde7 = { a9 8f [2] dd 97 [2] 9a 95 [2] dd 84 [2] 93 88 [2] 9f 82 [2] 88 89 [2] 93 c7 [2] ae }

  condition:
    any of them
}