rule TTP_XOR_MULT_DOSStub_fd8f {
  strings:
    $key_fd8f = { a9 e7 [2] dd ff [2] 9a fd [2] dd ec [2] 93 e0 [2] 9f ea [2] 88 e1 [2] 93 af [2] ae }

  condition:
    any of them
}