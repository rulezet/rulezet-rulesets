rule TTP_XOR_MULT_DOSStub_fd90 {
  strings:
    $key_fd90 = { a9 f8 [2] dd e0 [2] 9a e2 [2] dd f3 [2] 93 ff [2] 9f f5 [2] 88 fe [2] 93 b0 [2] ae }

  condition:
    any of them
}