rule TTP_XOR_MULT_DOSStub_27ce {
  strings:
    $key_27ce = { 73 a6 [2] 07 be [2] 40 bc [2] 07 ad [2] 49 a1 [2] 45 ab [2] 52 a0 [2] 49 ee [2] 74 }

  condition:
    any of them
}