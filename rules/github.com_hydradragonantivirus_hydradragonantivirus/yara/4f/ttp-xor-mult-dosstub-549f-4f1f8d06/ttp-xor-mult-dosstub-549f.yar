rule TTP_XOR_MULT_DOSStub_549f {
  strings:
    $key_549f = { 00 f7 [2] 74 ef [2] 33 ed [2] 74 fc [2] 3a f0 [2] 36 fa [2] 21 f1 [2] 3a bf [2] 07 }

  condition:
    any of them
}