rule TTP_XOR_MULT_DOSStub_ec9f {
  strings:
    $key_ec9f = { b8 f7 [2] cc ef [2] 8b ed [2] cc fc [2] 82 f0 [2] 8e fa [2] 99 f1 [2] 82 bf [2] bf }

  condition:
    any of them
}