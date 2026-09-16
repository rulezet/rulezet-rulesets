rule TTP_XOR_MULT_DOSStub_fd9f {
  strings:
    $key_fd9f = { a9 f7 [2] dd ef [2] 9a ed [2] dd fc [2] 93 f0 [2] 9f fa [2] 88 f1 [2] 93 bf [2] ae }

  condition:
    any of them
}