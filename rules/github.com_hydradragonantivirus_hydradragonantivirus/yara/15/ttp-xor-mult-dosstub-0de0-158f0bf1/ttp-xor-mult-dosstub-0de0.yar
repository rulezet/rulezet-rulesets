rule TTP_XOR_MULT_DOSStub_0de0 {
  strings:
    $key_0de0 = { 59 88 [2] 2d 90 [2] 6a 92 [2] 2d 83 [2] 63 8f [2] 6f 85 [2] 78 8e [2] 63 c0 [2] 5e }

  condition:
    any of them
}