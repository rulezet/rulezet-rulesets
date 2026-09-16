rule TTP_XOR_MULT_DOSStub_fd6c {
  strings:
    $key_fd6c = { a9 04 [2] dd 1c [2] 9a 1e [2] dd 0f [2] 93 03 [2] 9f 09 [2] 88 02 [2] 93 4c [2] ae }

  condition:
    any of them
}