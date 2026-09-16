rule TTP_XOR_MULT_DOSStub_6a16 {
  strings:
    $key_6a16 = { 3e 7e [2] 4a 66 [2] 0d 64 [2] 4a 75 [2] 04 79 [2] 08 73 [2] 1f 78 [2] 04 36 [2] 39 }

  condition:
    any of them
}