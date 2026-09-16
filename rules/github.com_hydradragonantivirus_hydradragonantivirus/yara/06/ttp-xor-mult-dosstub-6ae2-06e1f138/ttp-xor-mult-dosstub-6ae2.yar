rule TTP_XOR_MULT_DOSStub_6ae2 {
  strings:
    $key_6ae2 = { 3e 8a [2] 4a 92 [2] 0d 90 [2] 4a 81 [2] 04 8d [2] 08 87 [2] 1f 8c [2] 04 c2 [2] 39 }

  condition:
    any of them
}