rule TTP_XOR_MULT_DOSStub_9891 {
  strings:
    $key_9891 = { cc f9 [2] b8 e1 [2] ff e3 [2] b8 f2 [2] f6 fe [2] fa f4 [2] ed ff [2] f6 b1 [2] cb }

  condition:
    any of them
}