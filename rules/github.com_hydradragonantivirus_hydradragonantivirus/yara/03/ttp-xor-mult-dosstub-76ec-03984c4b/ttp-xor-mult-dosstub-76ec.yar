rule TTP_XOR_MULT_DOSStub_76ec {
  strings:
    $key_76ec = { 22 84 [2] 56 9c [2] 11 9e [2] 56 8f [2] 18 83 [2] 14 89 [2] 03 82 [2] 18 cc [2] 25 }

  condition:
    any of them
}