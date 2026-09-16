rule TTP_XOR_MULT_DOSStub_071e {
  strings:
    $key_071e = { 53 76 [2] 27 6e [2] 60 6c [2] 27 7d [2] 69 71 [2] 65 7b [2] 72 70 [2] 69 3e [2] 54 }

  condition:
    any of them
}