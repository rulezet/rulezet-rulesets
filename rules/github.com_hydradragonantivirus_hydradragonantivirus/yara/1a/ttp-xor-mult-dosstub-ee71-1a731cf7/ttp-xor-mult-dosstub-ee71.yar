rule TTP_XOR_MULT_DOSStub_ee71 {
  strings:
    $key_ee71 = { ba 19 [2] ce 01 [2] 89 03 [2] ce 12 [2] 80 1e [2] 8c 14 [2] 9b 1f [2] 80 51 [2] bd }

  condition:
    any of them
}