rule TTP_XOR_MULT_DOSStub_f29f {
  strings:
    $key_f29f = { a6 f7 [2] d2 ef [2] 95 ed [2] d2 fc [2] 9c f0 [2] 90 fa [2] 87 f1 [2] 9c bf [2] a1 }

  condition:
    any of them
}