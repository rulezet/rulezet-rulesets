rule TTP_XOR_MULT_DOSStub_9f8a {
  strings:
    $key_9f8a = { cb e2 [2] bf fa [2] f8 f8 [2] bf e9 [2] f1 e5 [2] fd ef [2] ea e4 [2] f1 aa [2] cc }

  condition:
    any of them
}