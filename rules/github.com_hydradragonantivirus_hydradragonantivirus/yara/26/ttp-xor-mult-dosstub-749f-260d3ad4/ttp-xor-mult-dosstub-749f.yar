rule TTP_XOR_MULT_DOSStub_749f {
  strings:
    $key_749f = { 20 f7 [2] 54 ef [2] 13 ed [2] 54 fc [2] 1a f0 [2] 16 fa [2] 01 f1 [2] 1a bf [2] 27 }

  condition:
    any of them
}