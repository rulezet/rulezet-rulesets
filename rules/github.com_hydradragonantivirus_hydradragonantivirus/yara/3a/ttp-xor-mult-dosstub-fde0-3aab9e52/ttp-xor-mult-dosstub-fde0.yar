rule TTP_XOR_MULT_DOSStub_fde0 {
  strings:
    $key_fde0 = { a9 88 [2] dd 90 [2] 9a 92 [2] dd 83 [2] 93 8f [2] 9f 85 [2] 88 8e [2] 93 c0 [2] ae }

  condition:
    any of them
}