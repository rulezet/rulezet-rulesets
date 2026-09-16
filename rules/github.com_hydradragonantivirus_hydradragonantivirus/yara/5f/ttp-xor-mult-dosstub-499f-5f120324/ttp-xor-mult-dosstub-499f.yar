rule TTP_XOR_MULT_DOSStub_499f {
  strings:
    $key_499f = { 1d f7 [2] 69 ef [2] 2e ed [2] 69 fc [2] 27 f0 [2] 2b fa [2] 3c f1 [2] 27 bf [2] 1a }

  condition:
    any of them
}