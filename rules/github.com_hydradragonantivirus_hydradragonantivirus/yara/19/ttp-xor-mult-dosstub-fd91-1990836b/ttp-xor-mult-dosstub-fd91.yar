rule TTP_XOR_MULT_DOSStub_fd91 {
  strings:
    $key_fd91 = { a9 f9 [2] dd e1 [2] 9a e3 [2] dd f2 [2] 93 fe [2] 9f f4 [2] 88 ff [2] 93 b1 [2] ae }

  condition:
    any of them
}