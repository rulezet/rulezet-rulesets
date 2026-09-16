rule TTP_XOR_MULT_DOSStub_a19f {
  strings:
    $key_a19f = { f5 f7 [2] 81 ef [2] c6 ed [2] 81 fc [2] cf f0 [2] c3 fa [2] d4 f1 [2] cf bf [2] f2 }

  condition:
    any of them
}