rule TTP_XOR_MULT_DOSStub_449f {
  strings:
    $key_449f = { 10 f7 [2] 64 ef [2] 23 ed [2] 64 fc [2] 2a f0 [2] 26 fa [2] 31 f1 [2] 2a bf [2] 17 }

  condition:
    any of them
}