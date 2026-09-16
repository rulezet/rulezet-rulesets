rule TTP_XOR_MULT_DOSStub_fd0b {
  strings:
    $key_fd0b = { a9 63 [2] dd 7b [2] 9a 79 [2] dd 68 [2] 93 64 [2] 9f 6e [2] 88 65 [2] 93 2b [2] ae }

  condition:
    any of them
}