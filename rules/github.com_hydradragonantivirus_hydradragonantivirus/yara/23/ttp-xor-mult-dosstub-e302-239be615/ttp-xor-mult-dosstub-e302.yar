rule TTP_XOR_MULT_DOSStub_e302 {
  strings:
    $key_e302 = { b7 6a [2] c3 72 [2] 84 70 [2] c3 61 [2] 8d 6d [2] 81 67 [2] 96 6c [2] 8d 22 [2] b0 }

  condition:
    any of them
}