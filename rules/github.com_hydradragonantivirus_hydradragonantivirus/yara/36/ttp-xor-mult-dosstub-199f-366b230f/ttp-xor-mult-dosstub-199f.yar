rule TTP_XOR_MULT_DOSStub_199f {
  strings:
    $key_199f = { 4d f7 [2] 39 ef [2] 7e ed [2] 39 fc [2] 77 f0 [2] 7b fa [2] 6c f1 [2] 77 bf [2] 4a }

  condition:
    any of them
}