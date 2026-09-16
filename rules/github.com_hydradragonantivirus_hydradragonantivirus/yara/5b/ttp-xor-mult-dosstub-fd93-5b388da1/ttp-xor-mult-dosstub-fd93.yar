rule TTP_XOR_MULT_DOSStub_fd93 {
  strings:
    $key_fd93 = { a9 fb [2] dd e3 [2] 9a e1 [2] dd f0 [2] 93 fc [2] 9f f6 [2] 88 fd [2] 93 b3 [2] ae }

  condition:
    any of them
}