rule TTP_XOR_MULT_DOSStub_fd95 {
  strings:
    $key_fd95 = { a9 fd [2] dd e5 [2] 9a e7 [2] dd f6 [2] 93 fa [2] 9f f0 [2] 88 fb [2] 93 b5 [2] ae }

  condition:
    any of them
}