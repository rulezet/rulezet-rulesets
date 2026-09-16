rule TTP_XOR_MULT_DOSStub_fd9d {
  strings:
    $key_fd9d = { a9 f5 [2] dd ed [2] 9a ef [2] dd fe [2] 93 f2 [2] 9f f8 [2] 88 f3 [2] 93 bd [2] ae }

  condition:
    any of them
}