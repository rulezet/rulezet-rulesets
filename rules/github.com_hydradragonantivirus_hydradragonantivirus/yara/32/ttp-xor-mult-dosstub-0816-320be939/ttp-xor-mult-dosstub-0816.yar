rule TTP_XOR_MULT_DOSStub_0816 {
  strings:
    $key_0816 = { 5c 7e [2] 28 66 [2] 6f 64 [2] 28 75 [2] 66 79 [2] 6a 73 [2] 7d 78 [2] 66 36 [2] 5b }

  condition:
    any of them
}