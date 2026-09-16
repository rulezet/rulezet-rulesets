rule TTP_XOR_MULT_DOSStub_512b {
  strings:
    $key_512b = { 05 43 [2] 71 5b [2] 36 59 [2] 71 48 [2] 3f 44 [2] 33 4e [2] 24 45 [2] 3f 0b [2] 02 }

  condition:
    any of them
}