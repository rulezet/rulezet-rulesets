rule TTP_XOR_MULT_DOSStub_001e {
  strings:
    $key_001e = { 54 76 [2] 20 6e [2] 67 6c [2] 20 7d [2] 6e 71 [2] 62 7b [2] 75 70 [2] 6e 3e [2] 53 }

  condition:
    any of them
}