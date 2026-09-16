rule TTP_XOR_MULT_DOSStub_512e {
  strings:
    $key_512e = { 05 46 [2] 71 5e [2] 36 5c [2] 71 4d [2] 3f 41 [2] 33 4b [2] 24 40 [2] 3f 0e [2] 02 }

  condition:
    any of them
}