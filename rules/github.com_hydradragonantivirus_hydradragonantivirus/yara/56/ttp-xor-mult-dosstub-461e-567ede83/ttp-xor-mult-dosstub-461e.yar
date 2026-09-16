rule TTP_XOR_MULT_DOSStub_461e {
  strings:
    $key_461e = { 12 76 [2] 66 6e [2] 21 6c [2] 66 7d [2] 28 71 [2] 24 7b [2] 33 70 [2] 28 3e [2] 15 }

  condition:
    any of them
}