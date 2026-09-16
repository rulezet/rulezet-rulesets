rule TTP_XOR_MULT_DOSStub_ea66 {
  strings:
    $key_ea66 = { be 0e [2] ca 16 [2] 8d 14 [2] ca 05 [2] 84 09 [2] 88 03 [2] 9f 08 [2] 84 46 [2] b9 }

  condition:
    any of them
}