rule TTP_XOR_MULT_DOSStub_ead0 {
  strings:
    $key_ead0 = { be b8 [2] ca a0 [2] 8d a2 [2] ca b3 [2] 84 bf [2] 88 b5 [2] 9f be [2] 84 f0 [2] b9 }

  condition:
    any of them
}