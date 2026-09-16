rule TTP_XOR_MULT_DOSStub_331e {
  strings:
    $key_331e = { 67 76 [2] 13 6e [2] 54 6c [2] 13 7d [2] 5d 71 [2] 51 7b [2] 46 70 [2] 5d 3e [2] 60 }

  condition:
    any of them
}