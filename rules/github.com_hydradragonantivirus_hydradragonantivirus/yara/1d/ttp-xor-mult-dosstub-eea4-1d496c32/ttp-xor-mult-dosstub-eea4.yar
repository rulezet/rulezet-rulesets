rule TTP_XOR_MULT_DOSStub_eea4 {
  strings:
    $key_eea4 = { ba cc [2] ce d4 [2] 89 d6 [2] ce c7 [2] 80 cb [2] 8c c1 [2] 9b ca [2] 80 84 [2] bd }

  condition:
    any of them
}