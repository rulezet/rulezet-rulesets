rule TTP_XOR_MULT_DOSStub_561e {
  strings:
    $key_561e = { 02 76 [2] 76 6e [2] 31 6c [2] 76 7d [2] 38 71 [2] 34 7b [2] 23 70 [2] 38 3e [2] 05 }

  condition:
    any of them
}