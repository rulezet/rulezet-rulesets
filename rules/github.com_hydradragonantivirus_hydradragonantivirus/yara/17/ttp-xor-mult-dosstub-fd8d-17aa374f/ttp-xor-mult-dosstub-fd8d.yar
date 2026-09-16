rule TTP_XOR_MULT_DOSStub_fd8d {
  strings:
    $key_fd8d = { a9 e5 [2] dd fd [2] 9a ff [2] dd ee [2] 93 e2 [2] 9f e8 [2] 88 e3 [2] 93 ad [2] ae }

  condition:
    any of them
}