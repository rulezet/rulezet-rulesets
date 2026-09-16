rule TTP_XOR_MULT_DOSStub_ee4b {
  strings:
    $key_ee4b = { ba 23 [2] ce 3b [2] 89 39 [2] ce 28 [2] 80 24 [2] 8c 2e [2] 9b 25 [2] 80 6b [2] bd }

  condition:
    any of them
}