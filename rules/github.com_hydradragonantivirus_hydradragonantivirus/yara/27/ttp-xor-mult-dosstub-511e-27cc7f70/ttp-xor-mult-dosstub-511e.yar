rule TTP_XOR_MULT_DOSStub_511e {
  strings:
    $key_511e = { 05 76 [2] 71 6e [2] 36 6c [2] 71 7d [2] 3f 71 [2] 33 7b [2] 24 70 [2] 3f 3e [2] 02 }

  condition:
    any of them
}