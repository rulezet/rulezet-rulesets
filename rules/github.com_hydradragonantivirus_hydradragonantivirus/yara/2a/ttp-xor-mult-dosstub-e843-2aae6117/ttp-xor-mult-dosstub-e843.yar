rule TTP_XOR_MULT_DOSStub_e843 {
  strings:
    $key_e843 = { bc 2b [2] c8 33 [2] 8f 31 [2] c8 20 [2] 86 2c [2] 8a 26 [2] 9d 2d [2] 86 63 [2] bb }

  condition:
    any of them
}