rule TTP_XOR_MULT_DOSStub_fd2f {
  strings:
    $key_fd2f = { a9 47 [2] dd 5f [2] 9a 5d [2] dd 4c [2] 93 40 [2] 9f 4a [2] 88 41 [2] 93 0f [2] ae }

  condition:
    any of them
}