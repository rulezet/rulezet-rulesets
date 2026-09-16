rule TTP_XOR_MULT_DOSStub_ee1e {
  strings:
    $key_ee1e = { ba 76 [2] ce 6e [2] 89 6c [2] ce 7d [2] 80 71 [2] 8c 7b [2] 9b 70 [2] 80 3e [2] bd }

  condition:
    any of them
}