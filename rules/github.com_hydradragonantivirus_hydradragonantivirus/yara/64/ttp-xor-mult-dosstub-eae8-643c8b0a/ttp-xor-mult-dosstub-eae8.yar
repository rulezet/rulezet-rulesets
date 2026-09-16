rule TTP_XOR_MULT_DOSStub_eae8 {
  strings:
    $key_eae8 = { be 80 [2] ca 98 [2] 8d 9a [2] ca 8b [2] 84 87 [2] 88 8d [2] 9f 86 [2] 84 c8 [2] b9 }

  condition:
    any of them
}