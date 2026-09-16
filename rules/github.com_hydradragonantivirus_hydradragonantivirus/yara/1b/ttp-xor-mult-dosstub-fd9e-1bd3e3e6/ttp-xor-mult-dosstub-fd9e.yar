rule TTP_XOR_MULT_DOSStub_fd9e {
  strings:
    $key_fd9e = { a9 f6 [2] dd ee [2] 9a ec [2] dd fd [2] 93 f1 [2] 9f fb [2] 88 f0 [2] 93 be [2] ae }

  condition:
    any of them
}