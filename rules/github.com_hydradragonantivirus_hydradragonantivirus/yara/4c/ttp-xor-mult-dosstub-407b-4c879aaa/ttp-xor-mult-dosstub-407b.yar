rule TTP_XOR_MULT_DOSStub_407b {
  strings:
    $key_407b = { 14 13 [2] 60 0b [2] 27 09 [2] 60 18 [2] 2e 14 [2] 22 1e [2] 35 15 [2] 2e 5b [2] 13 }

  condition:
    any of them
}