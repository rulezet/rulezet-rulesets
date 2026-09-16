rule TTP_XOR_MULT_DOSStub_fe14 {
  strings:
    $key_fe14 = { aa 7c [2] de 64 [2] 99 66 [2] de 77 [2] 90 7b [2] 9c 71 [2] 8b 7a [2] 90 34 [2] ad }

  condition:
    any of them
}