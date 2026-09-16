rule TTP_XOR_MULT_DOSStub_fd67 {
  strings:
    $key_fd67 = { a9 0f [2] dd 17 [2] 9a 15 [2] dd 04 [2] 93 08 [2] 9f 02 [2] 88 09 [2] 93 47 [2] ae }

  condition:
    any of them
}