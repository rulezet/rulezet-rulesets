rule TTP_XOR_MULT_DOSStub_761e {
  strings:
    $key_761e = { 22 76 [2] 56 6e [2] 11 6c [2] 56 7d [2] 18 71 [2] 14 7b [2] 03 70 [2] 18 3e [2] 25 }

  condition:
    any of them
}