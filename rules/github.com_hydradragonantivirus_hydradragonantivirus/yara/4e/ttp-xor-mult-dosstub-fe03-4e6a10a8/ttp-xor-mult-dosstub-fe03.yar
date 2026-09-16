rule TTP_XOR_MULT_DOSStub_fe03 {
  strings:
    $key_fe03 = { aa 6b [2] de 73 [2] 99 71 [2] de 60 [2] 90 6c [2] 9c 66 [2] 8b 6d [2] 90 23 [2] ad }

  condition:
    any of them
}