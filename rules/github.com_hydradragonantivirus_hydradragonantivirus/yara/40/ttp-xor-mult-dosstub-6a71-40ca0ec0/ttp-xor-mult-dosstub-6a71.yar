rule TTP_XOR_MULT_DOSStub_6a71 {
  strings:
    $key_6a71 = { 3e 19 [2] 4a 01 [2] 0d 03 [2] 4a 12 [2] 04 1e [2] 08 14 [2] 1f 1f [2] 04 51 [2] 39 }

  condition:
    any of them
}