rule TTP_XOR_MULT_DOSStub_6af5 {
  strings:
    $key_6af5 = { 3e 9d [2] 4a 85 [2] 0d 87 [2] 4a 96 [2] 04 9a [2] 08 90 [2] 1f 9b [2] 04 d5 [2] 39 }

  condition:
    any of them
}