rule TTP_XOR_MULT_DOSStub_ee2b {
  strings:
    $key_ee2b = { ba 43 [2] ce 5b [2] 89 59 [2] ce 48 [2] 80 44 [2] 8c 4e [2] 9b 45 [2] 80 0b [2] bd }

  condition:
    any of them
}