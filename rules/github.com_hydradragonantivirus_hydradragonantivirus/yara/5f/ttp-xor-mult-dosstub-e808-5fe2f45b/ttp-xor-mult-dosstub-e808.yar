rule TTP_XOR_MULT_DOSStub_e808 {
  strings:
    $key_e808 = { bc 60 [2] c8 78 [2] 8f 7a [2] c8 6b [2] 86 67 [2] 8a 6d [2] 9d 66 [2] 86 28 [2] bb }

  condition:
    any of them
}