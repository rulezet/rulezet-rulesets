rule TTP_XOR_MULT_DOSStub_8a9f {
  strings:
    $key_8a9f = { de f7 [2] aa ef [2] ed ed [2] aa fc [2] e4 f0 [2] e8 fa [2] ff f1 [2] e4 bf [2] d9 }

  condition:
    any of them
}