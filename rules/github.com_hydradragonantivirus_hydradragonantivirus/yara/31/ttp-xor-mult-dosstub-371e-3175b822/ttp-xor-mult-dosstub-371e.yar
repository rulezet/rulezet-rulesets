rule TTP_XOR_MULT_DOSStub_371e {
  strings:
    $key_371e = { 63 76 [2] 17 6e [2] 50 6c [2] 17 7d [2] 59 71 [2] 55 7b [2] 42 70 [2] 59 3e [2] 64 }

  condition:
    any of them
}