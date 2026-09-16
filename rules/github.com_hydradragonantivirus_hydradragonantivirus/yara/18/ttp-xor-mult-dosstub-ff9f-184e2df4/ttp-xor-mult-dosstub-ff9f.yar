rule TTP_XOR_MULT_DOSStub_ff9f {
  strings:
    $key_ff9f = { ab f7 [2] df ef [2] 98 ed [2] df fc [2] 91 f0 [2] 9d fa [2] 8a f1 [2] 91 bf [2] ac }

  condition:
    any of them
}