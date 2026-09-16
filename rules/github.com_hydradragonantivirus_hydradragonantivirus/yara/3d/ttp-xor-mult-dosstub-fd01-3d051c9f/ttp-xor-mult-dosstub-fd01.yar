rule TTP_XOR_MULT_DOSStub_fd01 {
  strings:
    $key_fd01 = { a9 69 [2] dd 71 [2] 9a 73 [2] dd 62 [2] 93 6e [2] 9f 64 [2] 88 6f [2] 93 21 [2] ae }

  condition:
    any of them
}