rule TTP_XOR_MULT_DOSStub_9892 {
  strings:
    $key_9892 = { cc fa [2] b8 e2 [2] ff e0 [2] b8 f1 [2] f6 fd [2] fa f7 [2] ed fc [2] f6 b2 [2] cb }

  condition:
    any of them
}