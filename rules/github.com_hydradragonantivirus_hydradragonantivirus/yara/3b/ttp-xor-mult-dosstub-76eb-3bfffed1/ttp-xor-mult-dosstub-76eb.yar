rule TTP_XOR_MULT_DOSStub_76eb {
  strings:
    $key_76eb = { 22 83 [2] 56 9b [2] 11 99 [2] 56 88 [2] 18 84 [2] 14 8e [2] 03 85 [2] 18 cb [2] 25 }

  condition:
    any of them
}