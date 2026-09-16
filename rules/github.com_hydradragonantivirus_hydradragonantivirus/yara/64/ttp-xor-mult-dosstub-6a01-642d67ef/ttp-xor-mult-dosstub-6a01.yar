rule TTP_XOR_MULT_DOSStub_6a01 {
  strings:
    $key_6a01 = { 3e 69 [2] 4a 71 [2] 0d 73 [2] 4a 62 [2] 04 6e [2] 08 64 [2] 1f 6f [2] 04 21 [2] 39 }

  condition:
    any of them
}