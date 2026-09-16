rule TTP_XOR_MULT_DOSStub_cc9f {
  strings:
    $key_cc9f = { 98 f7 [2] ec ef [2] ab ed [2] ec fc [2] a2 f0 [2] ae fa [2] b9 f1 [2] a2 bf [2] 9f }

  condition:
    any of them
}