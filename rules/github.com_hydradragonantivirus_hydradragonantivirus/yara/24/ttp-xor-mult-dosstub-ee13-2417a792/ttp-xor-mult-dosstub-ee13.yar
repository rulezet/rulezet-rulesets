rule TTP_XOR_MULT_DOSStub_ee13 {
  strings:
    $key_ee13 = { ba 7b [2] ce 63 [2] 89 61 [2] ce 70 [2] 80 7c [2] 8c 76 [2] 9b 7d [2] 80 33 [2] bd }

  condition:
    any of them
}