rule TTP_XOR_MULT_DOSStub_ee24 {
  strings:
    $key_ee24 = { ba 4c [2] ce 54 [2] 89 56 [2] ce 47 [2] 80 4b [2] 8c 41 [2] 9b 4a [2] 80 04 [2] bd }

  condition:
    any of them
}