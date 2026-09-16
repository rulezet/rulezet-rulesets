rule TTP_XOR_MULT_DOSStub_fde1 {
  strings:
    $key_fde1 = { a9 89 [2] dd 91 [2] 9a 93 [2] dd 82 [2] 93 8e [2] 9f 84 [2] 88 8f [2] 93 c1 [2] ae }

  condition:
    any of them
}