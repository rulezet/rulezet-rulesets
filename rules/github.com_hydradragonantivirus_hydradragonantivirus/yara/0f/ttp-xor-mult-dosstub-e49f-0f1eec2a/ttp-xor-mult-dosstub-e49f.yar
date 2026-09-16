rule TTP_XOR_MULT_DOSStub_e49f {
  strings:
    $key_e49f = { b0 f7 [2] c4 ef [2] 83 ed [2] c4 fc [2] 8a f0 [2] 86 fa [2] 91 f1 [2] 8a bf [2] b7 }

  condition:
    any of them
}