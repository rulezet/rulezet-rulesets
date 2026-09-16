rule TTP_XOR_MULT_DOSStub_251e {
  strings:
    $key_251e = { 71 76 [2] 05 6e [2] 42 6c [2] 05 7d [2] 4b 71 [2] 47 7b [2] 50 70 [2] 4b 3e [2] 76 }

  condition:
    any of them
}