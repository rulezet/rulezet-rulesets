rule TTP_XOR_MULT_DOSStub_411b {
  strings:
    $key_411b = { 15 73 [2] 61 6b [2] 26 69 [2] 61 78 [2] 2f 74 [2] 23 7e [2] 34 75 [2] 2f 3b [2] 12 }

  condition:
    any of them
}