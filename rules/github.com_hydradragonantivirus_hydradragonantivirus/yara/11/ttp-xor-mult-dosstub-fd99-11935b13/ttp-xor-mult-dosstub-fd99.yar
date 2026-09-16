rule TTP_XOR_MULT_DOSStub_fd99 {
  strings:
    $key_fd99 = { a9 f1 [2] dd e9 [2] 9a eb [2] dd fa [2] 93 f6 [2] 9f fc [2] 88 f7 [2] 93 b9 [2] ae }

  condition:
    any of them
}