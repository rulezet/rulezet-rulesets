rule TTP_XOR_MULT_DOSStub_135c {
  strings:
    $key_135c = { 47 34 [2] 33 2c [2] 74 2e [2] 33 3f [2] 7d 33 [2] 71 39 [2] 66 32 [2] 7d 7c [2] 40 }

  condition:
    any of them
}