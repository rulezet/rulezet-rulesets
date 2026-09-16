rule TTP_XOR_MULT_DOSStub_e853 {
  strings:
    $key_e853 = { bc 3b [2] c8 23 [2] 8f 21 [2] c8 30 [2] 86 3c [2] 8a 36 [2] 9d 3d [2] 86 73 [2] bb }

  condition:
    any of them
}