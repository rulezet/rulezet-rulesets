rule TTP_XOR_MULT_DOSStub_fe53 {
  strings:
    $key_fe53 = { aa 3b [2] de 23 [2] 99 21 [2] de 30 [2] 90 3c [2] 9c 36 [2] 8b 3d [2] 90 73 [2] ad }

  condition:
    any of them
}