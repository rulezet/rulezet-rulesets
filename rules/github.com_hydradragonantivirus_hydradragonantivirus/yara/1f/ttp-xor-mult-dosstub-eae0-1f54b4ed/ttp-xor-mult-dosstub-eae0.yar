rule TTP_XOR_MULT_DOSStub_eae0 {
  strings:
    $key_eae0 = { be 88 [2] ca 90 [2] 8d 92 [2] ca 83 [2] 84 8f [2] 88 85 [2] 9f 8e [2] 84 c0 [2] b9 }

  condition:
    any of them
}