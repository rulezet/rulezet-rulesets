rule TTP_XOR_MULT_DOSStub_1f5c {
  strings:
    $key_1f5c = { 4b 34 [2] 3f 2c [2] 78 2e [2] 3f 3f [2] 71 33 [2] 7d 39 [2] 6a 32 [2] 71 7c [2] 4c }

  condition:
    any of them
}