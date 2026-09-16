rule TTP_XOR_MULT_DOSStub_639f {
  strings:
    $key_639f = { 37 f7 [2] 43 ef [2] 04 ed [2] 43 fc [2] 0d f0 [2] 01 fa [2] 16 f1 [2] 0d bf [2] 30 }

  condition:
    any of them
}