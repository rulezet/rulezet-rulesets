rule TTP_XOR_MULT_DOSStub_5e16 {
  strings:
    $key_5e16 = { 0a 7e [2] 7e 66 [2] 39 64 [2] 7e 75 [2] 30 79 [2] 3c 73 [2] 2b 78 [2] 30 36 [2] 0d }

  condition:
    any of them
}