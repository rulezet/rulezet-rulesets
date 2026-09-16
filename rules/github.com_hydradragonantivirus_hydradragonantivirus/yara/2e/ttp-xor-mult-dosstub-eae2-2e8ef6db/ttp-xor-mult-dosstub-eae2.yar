rule TTP_XOR_MULT_DOSStub_eae2 {
  strings:
    $key_eae2 = { be 8a [2] ca 92 [2] 8d 90 [2] ca 81 [2] 84 8d [2] 88 87 [2] 9f 8c [2] 84 c2 [2] b9 }

  condition:
    any of them
}