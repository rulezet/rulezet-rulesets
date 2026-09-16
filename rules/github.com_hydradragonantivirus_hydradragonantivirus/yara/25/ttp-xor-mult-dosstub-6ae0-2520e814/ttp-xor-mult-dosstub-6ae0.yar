rule TTP_XOR_MULT_DOSStub_6ae0 {
  strings:
    $key_6ae0 = { 3e 88 [2] 4a 90 [2] 0d 92 [2] 4a 83 [2] 04 8f [2] 08 85 [2] 1f 8e [2] 04 c0 [2] 39 }

  condition:
    any of them
}