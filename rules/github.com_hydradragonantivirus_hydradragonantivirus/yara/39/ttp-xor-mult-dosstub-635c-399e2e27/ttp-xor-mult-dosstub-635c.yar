rule TTP_XOR_MULT_DOSStub_635c {
  strings:
    $key_635c = { 37 34 [2] 43 2c [2] 04 2e [2] 43 3f [2] 0d 33 [2] 01 39 [2] 16 32 [2] 0d 7c [2] 30 }

  condition:
    any of them
}