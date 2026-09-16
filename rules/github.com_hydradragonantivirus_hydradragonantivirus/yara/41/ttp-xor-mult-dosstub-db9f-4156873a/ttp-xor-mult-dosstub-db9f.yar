rule TTP_XOR_MULT_DOSStub_db9f {
  strings:
    $key_db9f = { 8f f7 [2] fb ef [2] bc ed [2] fb fc [2] b5 f0 [2] b9 fa [2] ae f1 [2] b5 bf [2] 88 }

  condition:
    any of them
}