rule TTP_XOR_MULT_DOSStub_e013 {
  strings:
    $key_e013 = { b4 7b [2] c0 63 [2] 87 61 [2] c0 70 [2] 8e 7c [2] 82 76 [2] 95 7d [2] 8e 33 [2] b3 }

  condition:
    any of them
}