rule TTP_XOR_MULT_DOSStub_ee73 {
  strings:
    $key_ee73 = { ba 1b [2] ce 03 [2] 89 01 [2] ce 10 [2] 80 1c [2] 8c 16 [2] 9b 1d [2] 80 53 [2] bd }

  condition:
    any of them
}